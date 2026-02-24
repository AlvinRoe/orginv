package orchestrator

import (
	"context"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	githubclient "github.com/AlvinRoe/orginv/internal/clients/github"
	"github.com/AlvinRoe/orginv/internal/config"
	"github.com/AlvinRoe/orginv/internal/report"
	"github.com/AlvinRoe/orginv/internal/store/sqlite"
	gogithub "github.com/google/go-github/v82/github"
)

type Runner struct {
	cfg      config.Config
	client   *githubclient.Client
	store    *sqlite.Store
	exporter *report.Exporter
}

type dbWriteOp struct {
	name     string
	priority int
	rows     int
	apply    func(context.Context) error
}

func NewRunner(cfg config.Config, client *githubclient.Client, store *sqlite.Store, exporter *report.Exporter) *Runner {
	return &Runner{cfg: cfg, client: client, store: store, exporter: exporter}
}

func (r *Runner) Run(ctx context.Context) error {
	if err := r.store.InitSchema(ctx); err != nil {
		return fmt.Errorf("failed to initialize sqlite schema: %w", err)
	}

	repos, err := r.client.FetchAllRepos(ctx, r.cfg.Org, r.cfg.ResultsPerPage)
	if err != nil {
		return fmt.Errorf("failed to fetch repositories: %w", err)
	}
	log.Printf("found %d repos", len(repos))

	repoIDByName, activeRepos, err := r.store.UpsertRepos(ctx, r.cfg.Org, repos)
	if err != nil {
		return fmt.Errorf("failed to persist repositories: %w", err)
	}
	log.Printf("active repos: %d", len(activeRepos))

	var errMu sync.Mutex
	errorsSeen := make([]string, 0)
	recordErr := func(msg string, err error) {
		errMu.Lock()
		defer errMu.Unlock()
		errorsSeen = append(errorsSeen, fmt.Sprintf("%s: %v", msg, err))
		log.Printf("%s: %v", msg, err)
	}

	writeOps := make([]dbWriteOp, 0, len(activeRepos)*2+3)
	var writeOpsMu sync.Mutex
	enqueueWriteOp := func(op dbWriteOp) {
		writeOpsMu.Lock()
		writeOps = append(writeOps, op)
		writeOpsMu.Unlock()
	}

	log.Printf("fetching org-level alert datasets")
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
				enqueueWriteOp(dbWriteOp{
					name:     "dependabot alerts",
					priority: 30,
					rows:     len(alerts),
					apply: func(ctx context.Context) error {
						return r.store.IngestDependabotAlerts(ctx, repoIDByName, alerts)
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
				enqueueWriteOp(dbWriteOp{
					name:     "code scanning alerts",
					priority: 30,
					rows:     len(alerts),
					apply: func(ctx context.Context) error {
						return r.store.IngestCodeScanningAlerts(ctx, repoIDByName, alerts)
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
				enqueueWriteOp(dbWriteOp{
					name:     "secret scanning alerts",
					priority: 30,
					rows:     len(alerts),
					apply: func(ctx context.Context) error {
						return r.store.IngestSecretScanningAlerts(ctx, repoIDByName, alerts)
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
				recordErr(fmt.Sprintf("%s ingestion failed", taskName), err)
				return
			}
			log.Printf("%s fetch/build done in %s", taskName, time.Since(started))
		}(task.name, task.run)
	}
	orgWG.Wait()

	log.Printf("fetching per-repo datasets (sbom)")
	const repoWorkers = 10
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
					recordErr(fmt.Sprintf("worker %d sbom %s", workerID, repoName), sbomErr)
				} else {
					enqueueWriteOp(dbWriteOp{
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

	log.Printf("all fetch phases complete; queued db operations=%d", len(writeOps))
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
			recordErr(fmt.Sprintf("db write failed: %s", op.name), err)
			continue
		}
		log.Printf("db queue %d/%d done: %s in %s", idx+1, len(writeOps), op.name, time.Since(started))
	}

	if err := r.exporter.ExportCSV(ctx, r.cfg.CSVOutputPath); err != nil {
		return fmt.Errorf("failed to export csv report: %w", err)
	}

	if len(errorsSeen) > 0 {
		log.Printf("completed with %d ingestion errors (see logs)", len(errorsSeen))
	}

	log.Printf("phase 1 complete")
	log.Printf("sqlite output: %s", r.cfg.SQLitePath)
	log.Printf("csv output: %s", r.cfg.CSVOutputPath)
	return nil
}
