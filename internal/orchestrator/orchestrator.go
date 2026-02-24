package orchestrator

import (
	"context"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/AlvinRoe/orginv/internal/config"
	"github.com/AlvinRoe/orginv/internal/store/sqlite"
	gogithub "github.com/google/go-github/v82/github"
)

const repoWorkers = 10

type Runner struct {
	cfg    config.Config
	client RepoFetcher
	store  Store
}

type RepoLoadResult struct {
	RepoIDByName sqlite.RepoIndex
	ActiveRepos  []*gogithub.Repository
}

type DatasetFetchResult struct {
	WriteOps []dbWriteOp
	Errors   []string
}

type dbWriteOp struct {
	name     string
	priority int
	rows     int
	apply    func(context.Context) error
}

type fetchCollector struct {
	writeOpsMu sync.Mutex
	writeOps   []dbWriteOp

	errorsMu sync.Mutex
	errors   []string
}

type RepoFetcher interface {
	FetchAllRepos(ctx context.Context, org string, perPage int) ([]*gogithub.Repository, error)
	FetchDependabotAlerts(ctx context.Context, org string, perPage int) ([]*gogithub.DependabotAlert, int, error)
	FetchCodeScanningAlerts(ctx context.Context, org string, perPage int) ([]*gogithub.Alert, int, error)
	FetchSecretScanningAlerts(ctx context.Context, org string, perPage int) ([]*gogithub.SecretScanningAlert, int, error)
	FetchSBOM(ctx context.Context, org, repo string) (*gogithub.SBOM, error)
}

type Store interface {
	InitSchema(ctx context.Context) error
	UpsertRepos(ctx context.Context, org string, repos []*gogithub.Repository) (sqlite.RepoIndex, []*gogithub.Repository, error)
	IngestSBOM(ctx context.Context, repoID int64, sbom *gogithub.SBOM) error
	IngestDependabotAlerts(ctx context.Context, repoIDByName sqlite.RepoIndex, alerts []*gogithub.DependabotAlert) error
	IngestCodeScanningAlerts(ctx context.Context, repoIDByName sqlite.RepoIndex, alerts []*gogithub.Alert) error
	IngestSecretScanningAlerts(ctx context.Context, repoIDByName sqlite.RepoIndex, alerts []*gogithub.SecretScanningAlert) error
	ExportCSVReport(ctx context.Context, outputPath string) error
}

func NewRunner(cfg config.Config, client RepoFetcher, store Store) *Runner {
	return &Runner{cfg: cfg, client: client, store: store}
}

func (r *Runner) Bootstrap(ctx context.Context) error {
	if err := r.store.InitSchema(ctx); err != nil {
		return fmt.Errorf("failed to initialize sqlite schema: %w", err)
	}
	return nil
}

func (r *Runner) LoadRepos(ctx context.Context) (RepoLoadResult, error) {
	repos, err := r.client.FetchAllRepos(ctx, r.cfg.Org, r.cfg.ResultsPerPage)
	if err != nil {
		return RepoLoadResult{}, fmt.Errorf("failed to fetch repositories: %w", err)
	}
	log.Printf("found %d repos", len(repos))

	repoIDByName, activeRepos, err := r.store.UpsertRepos(ctx, r.cfg.Org, repos)
	if err != nil {
		return RepoLoadResult{}, fmt.Errorf("failed to persist repositories: %w", err)
	}

	log.Printf("active repos: %d", len(activeRepos))
	return RepoLoadResult{
		RepoIDByName: repoIDByName,
		ActiveRepos:  activeRepos,
	}, nil
}

func (r *Runner) FetchDatasets(ctx context.Context, repos RepoLoadResult) DatasetFetchResult {
	collector := &fetchCollector{
		writeOps: make([]dbWriteOp, 0, len(repos.ActiveRepos)*2+3),
	}

	log.Printf("stage ingestion: fetching org-level alert datasets")
	r.fetchOrgAlertDatasets(ctx, repos, collector)

	log.Printf("stage ingestion: fetching per-repo datasets (sbom)")
	r.fetchSBOMDatasets(ctx, repos.ActiveRepos, collector)

	return DatasetFetchResult{
		WriteOps: collector.writeOps,
		Errors:   collector.errors,
	}
}

func (r *Runner) fetchOrgAlertDatasets(ctx context.Context, repos RepoLoadResult, collector *fetchCollector) {
	var orgWG sync.WaitGroup
	orgFetch := []struct {
		name string
		run  func() error
	}{
		{
			name: "dependabot",
			run: func() error {
				alerts, pages, err := r.client.FetchDependabotAlerts(ctx, r.cfg.Org, r.cfg.ResultsPerPage)
				if err != nil {
					return err
				}
				log.Printf("dependabot fetch complete: pages=%d alerts=%d", pages, len(alerts))
				collector.enqueueWriteOp(dbWriteOp{
					name:     "dependabot alerts",
					priority: 30,
					rows:     len(alerts),
					apply: func(ctx context.Context) error {
						return r.store.IngestDependabotAlerts(ctx, repos.RepoIDByName, alerts)
					},
				})
				return nil
			},
		},
		{
			name: "code scanning",
			run: func() error {
				alerts, pages, err := r.client.FetchCodeScanningAlerts(ctx, r.cfg.Org, r.cfg.ResultsPerPage)
				if err != nil {
					return err
				}
				log.Printf("code scanning fetch complete: pages=%d alerts=%d", pages, len(alerts))
				collector.enqueueWriteOp(dbWriteOp{
					name:     "code scanning alerts",
					priority: 30,
					rows:     len(alerts),
					apply: func(ctx context.Context) error {
						return r.store.IngestCodeScanningAlerts(ctx, repos.RepoIDByName, alerts)
					},
				})
				return nil
			},
		},
		{
			name: "secret scanning",
			run: func() error {
				alerts, pages, err := r.client.FetchSecretScanningAlerts(ctx, r.cfg.Org, r.cfg.ResultsPerPage)
				if err != nil {
					return err
				}
				log.Printf("secret scanning fetch complete: pages=%d alerts=%d", pages, len(alerts))
				collector.enqueueWriteOp(dbWriteOp{
					name:     "secret scanning alerts",
					priority: 30,
					rows:     len(alerts),
					apply: func(ctx context.Context) error {
						return r.store.IngestSecretScanningAlerts(ctx, repos.RepoIDByName, alerts)
					},
				})
				return nil
			},
		},
	}

	for _, task := range orgFetch {
		orgWG.Add(1)
		go func(taskName string, run func() error) {
			defer orgWG.Done()
			started := time.Now()
			log.Printf("%s fetch started", taskName)
			if err := run(); err != nil {
				collector.recordErr(fmt.Sprintf("%s ingestion failed", taskName), err)
				return
			}
			log.Printf("%s fetch/build done in %s", taskName, time.Since(started))
		}(task.name, task.run)
	}
	orgWG.Wait()
}

func (r *Runner) fetchSBOMDatasets(ctx context.Context, activeRepos []*gogithub.Repository, collector *fetchCollector) {
	repoChan := make(chan *gogithub.Repository, len(activeRepos))
	var repoWG sync.WaitGroup

	for i := 0; i < repoWorkers; i++ {
		repoWG.Add(1)
		go func(workerID int) {
			defer repoWG.Done()
			for repo := range repoChan {
				repoName := repo.GetName()
				repoID := repo.GetID()
				repoStart := time.Now()
				log.Printf("worker %d fetch started for repo %s", workerID, repoName)

				sbom, sbomErr := r.client.FetchSBOM(ctx, r.cfg.Org, repoName)
				if sbomErr != nil {
					collector.recordErr(fmt.Sprintf("worker %d sbom %s", workerID, repoName), sbomErr)
				} else {
					collector.enqueueWriteOp(dbWriteOp{
						name:     fmt.Sprintf("sbom %s", repoName),
						priority: 10,
						rows:     1,
						apply: func(ctx context.Context) error {
							return r.store.IngestSBOM(ctx, repoID, sbom)
						},
					})
				}

				log.Printf("worker %d fetch complete for repo %s in %s", workerID, repoName, time.Since(repoStart))
			}
		}(i + 1)
	}

	for _, repo := range activeRepos {
		repoChan <- repo
	}
	close(repoChan)
	repoWG.Wait()
}

func (r *Runner) ExecuteWrites(ctx context.Context, fetchResult DatasetFetchResult) []string {
	writeOps := append([]dbWriteOp(nil), fetchResult.WriteOps...)
	errorsSeen := append([]string(nil), fetchResult.Errors...)

	log.Printf("stage writes: queued db operations=%d", len(writeOps))
	sort.SliceStable(writeOps, func(i, j int) bool {
		if writeOps[i].priority == writeOps[j].priority {
			return writeOps[i].name < writeOps[j].name
		}
		return writeOps[i].priority < writeOps[j].priority
	})

	for idx, op := range writeOps {
		started := time.Now()
		log.Printf("db queue %d/%d start: %s (rows=%d)", idx+1, len(writeOps), op.name, op.rows)
		if err := op.apply(ctx); err != nil {
			msg := fmt.Sprintf("db write failed: %s: %v", op.name, err)
			errorsSeen = append(errorsSeen, msg)
			log.Printf("%s", msg)
			continue
		}
		log.Printf("db queue %d/%d done: %s in %s", idx+1, len(writeOps), op.name, time.Since(started))
	}

	return errorsSeen
}

func (r *Runner) ExportReport(ctx context.Context) error {
	if err := r.store.ExportCSVReport(ctx, r.cfg.CSVOutputPath); err != nil {
		return fmt.Errorf("failed to export csv report: %w", err)
	}
	return nil
}

func (r *Runner) Finalize(errorsSeen []string) {
	if len(errorsSeen) > 0 {
		log.Printf("completed with %d ingestion errors (see logs)", len(errorsSeen))
	}
	log.Printf("phase 1 complete")
	log.Printf("sqlite output: %s", r.cfg.SQLitePath)
	log.Printf("csv output: %s", r.cfg.CSVOutputPath)
}

func (c *fetchCollector) recordErr(msg string, err error) {
	c.errorsMu.Lock()
	defer c.errorsMu.Unlock()
	c.errors = append(c.errors, fmt.Sprintf("%s: %v", msg, err))
	log.Printf("%s: %v", msg, err)
}

func (c *fetchCollector) enqueueWriteOp(op dbWriteOp) {
	c.writeOpsMu.Lock()
	c.writeOps = append(c.writeOps, op)
	c.writeOpsMu.Unlock()
}
