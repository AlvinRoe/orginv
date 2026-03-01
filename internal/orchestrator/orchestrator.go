package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/AlvinRoe/orginv/internal/config"
	"github.com/AlvinRoe/orginv/internal/exporter"
	"github.com/AlvinRoe/orginv/internal/store/sqlite"
	gogithub "github.com/google/go-github/v82/github"
)

type Runner struct {
	cfg    config.Config
	client RepoFetcher
	store  Store
}

type RunContext struct {
	Config config.Config

	Repos        []*gogithub.Repository
	ActiveRepos  []*gogithub.Repository
	RepoIDByName sqlite.RepoIndex

	DependabotAlerts     []*gogithub.DependabotAlert
	CodeScanningAlerts   []*gogithub.Alert
	SecretScanningAlerts []*gogithub.SecretScanningAlert
	SBOMByRepoID         map[int64]*gogithub.SBOM

	Errors []string
}

type Stage interface {
	Name() string
	Run(context.Context, *RunContext) error
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
	IngestSBOMMain(ctx context.Context, repoID int64, sbom *gogithub.SBOM) error
	IngestSBOMLinks(ctx context.Context, repoID int64, sbom *gogithub.SBOM) error
	IngestDependabotAlertsMain(ctx context.Context, repoIDByName sqlite.RepoIndex, alerts []*gogithub.DependabotAlert) error
	IngestDependabotAlertsLinks(ctx context.Context, repoIDByName sqlite.RepoIndex, alerts []*gogithub.DependabotAlert) error
	IngestCodeScanningAlerts(ctx context.Context, repoIDByName sqlite.RepoIndex, alerts []*gogithub.Alert) error
	IngestSecretScanningAlerts(ctx context.Context, repoIDByName sqlite.RepoIndex, alerts []*gogithub.SecretScanningAlert) error
	RefreshVulnerableRepoPackages(ctx context.Context) error
	QueryReportData(ctx context.Context) (sqlite.ReportData, error)
}

func NewRunner(cfg config.Config, client RepoFetcher, store Store) *Runner {
	return &Runner{cfg: cfg, client: client, store: store}
}

func (r *Runner) Run(ctx context.Context) ([]string, error) {
	rc := &RunContext{
		Config:       r.cfg,
		SBOMByRepoID: make(map[int64]*gogithub.SBOM),
		Errors:       make([]string, 0, 16),
	}
	stages := []Stage{
		initSchemaStage{store: r.store},
		loadReposStage{runner: r},
		fetchDatasetsStage{runner: r},
		ingestMainStage{store: r.store},
		ingestLinksStage{store: r.store},
		deriveVulnerablePackagesStage{store: r.store},
		reportStage{store: r.store, outputPath: r.cfg.CSVOutputPath},
	}

	for _, stage := range stages {
		started := time.Now()
		log.Printf("stage %s started", stage.Name())
		if err := stage.Run(ctx, rc); err != nil {
			return rc.Errors, fmt.Errorf("%s failed: %w", stage.Name(), err)
		}
		log.Printf("stage %s completed in %s", stage.Name(), time.Since(started))
	}

	return rc.Errors, nil
}

func (r *Runner) Finalize(errorsSeen []string) {
	if len(errorsSeen) > 0 {
		log.Printf("completed with %d ingestion errors (see logs)", len(errorsSeen))
	}
	log.Printf("phase 1 complete")
	log.Printf("sqlite output: %s", r.cfg.SQLitePath)
	log.Printf("csv output: %s", r.cfg.CSVOutputPath)
}

type initSchemaStage struct {
	store Store
}

func (s initSchemaStage) Name() string { return "init-schema" }

func (s initSchemaStage) Run(ctx context.Context, rc *RunContext) error {
	return s.store.InitSchema(ctx)
}

type loadReposStage struct {
	runner *Runner
}

func (s loadReposStage) Name() string { return "load-repos" }

func (s loadReposStage) Run(ctx context.Context, rc *RunContext) error {
	repos, err := s.runner.client.FetchAllRepos(ctx, s.runner.cfg.Org, s.runner.cfg.ResultsPerPage)
	if err != nil {
		return fmt.Errorf("failed to fetch repositories: %w", err)
	}
	log.Printf("found %d repos", len(repos))

	repoIDByName, activeRepos, err := s.runner.store.UpsertRepos(ctx, s.runner.cfg.Org, repos)
	if err != nil {
		return fmt.Errorf("failed to persist repositories: %w", err)
	}

	rc.Repos = repos
	rc.ActiveRepos = activeRepos
	rc.RepoIDByName = repoIDByName
	log.Printf("active repos: %d", len(activeRepos))
	return nil
}

type fetchDatasetsStage struct {
	runner *Runner
}

func (s fetchDatasetsStage) Name() string { return "fetch-datasets" }

func (s fetchDatasetsStage) Run(ctx context.Context, rc *RunContext) error {
	var (
		wg     sync.WaitGroup
		errMu  sync.Mutex
		dataMu sync.Mutex
	)

	recordErr := func(label string, err error) {
		if err == nil {
			return
		}
		errMu.Lock()
		rc.Errors = append(rc.Errors, fmt.Sprintf("%s: %v", label, err))
		errMu.Unlock()
		log.Printf("%s: %v", label, err)
	}

	orgTasks := []struct {
		name string
		run  func(context.Context) error
	}{
		{
			name: "dependabot",
			run: func(ctx context.Context) error {
				alerts, pages, err := s.runner.client.FetchDependabotAlerts(ctx, s.runner.cfg.Org, s.runner.cfg.ResultsPerPage)
				if err != nil {
					return err
				}
				log.Printf("dependabot fetch complete: pages=%d alerts=%d", pages, len(alerts))
				dataMu.Lock()
				rc.DependabotAlerts = alerts
				dataMu.Unlock()
				return nil
			},
		},
		{
			name: "code scanning",
			run: func(ctx context.Context) error {
				alerts, pages, err := s.runner.client.FetchCodeScanningAlerts(ctx, s.runner.cfg.Org, s.runner.cfg.ResultsPerPage)
				if err != nil {
					return err
				}
				log.Printf("code scanning fetch complete: pages=%d alerts=%d", pages, len(alerts))
				dataMu.Lock()
				rc.CodeScanningAlerts = alerts
				dataMu.Unlock()
				return nil
			},
		},
		{
			name: "secret scanning",
			run: func(ctx context.Context) error {
				alerts, pages, err := s.runner.client.FetchSecretScanningAlerts(ctx, s.runner.cfg.Org, s.runner.cfg.ResultsPerPage)
				if err != nil {
					return err
				}
				log.Printf("secret scanning fetch complete: pages=%d alerts=%d", pages, len(alerts))
				dataMu.Lock()
				rc.SecretScanningAlerts = alerts
				dataMu.Unlock()
				return nil
			},
		},
	}

	for _, task := range orgTasks {
		task := task
		wg.Add(1)
		go func() {
			defer wg.Done()
			started := time.Now()
			log.Printf("%s fetch started", task.name)
			if err := task.run(ctx); err != nil {
				if isRateLimitErr(err) {
					log.Fatalf("fatal: GitHub rate limit encountered during %s fetch: %v", task.name, err)
				}
				recordErr(task.name, err)
				return
			}
			log.Printf("%s fetch completed in %s", task.name, time.Since(started))
		}()
	}

	repoChan := make(chan *gogithub.Repository, len(rc.ActiveRepos))
	var sbomWG sync.WaitGroup
	for i := 0; i < s.runner.cfg.SBOMWorkers; i++ {
		sbomWG.Add(1)
		go func(workerID int) {
			defer sbomWG.Done()
			for repo := range repoChan {
				repoName := repo.GetName()
				repoID := repo.GetID()
				started := time.Now()
				log.Printf("worker %d sbom fetch started for %s", workerID, repoName)
				sbom, err := s.runner.client.FetchSBOM(ctx, s.runner.cfg.Org, repoName)
				if err != nil {
					if isRateLimitErr(err) {
						log.Fatalf("fatal: GitHub rate limit encountered during sbom fetch (repo=%s): %v", repoName, err)
					}
					recordErr(fmt.Sprintf("sbom %s", repoName), err)
					continue
				}
				dataMu.Lock()
				rc.SBOMByRepoID[repoID] = sbom
				dataMu.Unlock()
				log.Printf("worker %d sbom fetch completed for %s in %s", workerID, repoName, time.Since(started))
			}
		}(i + 1)
	}

	for _, repo := range rc.ActiveRepos {
		repoChan <- repo
	}
	close(repoChan)

	wg.Wait()
	sbomWG.Wait()
	return nil
}

type ingestMainStage struct {
	store Store
}

func (s ingestMainStage) Name() string { return "ingest-main" }

func (s ingestMainStage) Run(ctx context.Context, rc *RunContext) error {
	for _, job := range []struct {
		name string
		run  func() error
	}{
		{
			name: "dependabot-main",
			run:  func() error { return s.store.IngestDependabotAlertsMain(ctx, rc.RepoIDByName, rc.DependabotAlerts) },
		},
		{
			name: "code-scanning",
			run:  func() error { return s.store.IngestCodeScanningAlerts(ctx, rc.RepoIDByName, rc.CodeScanningAlerts) },
		},
		{
			name: "secret-scanning",
			run:  func() error { return s.store.IngestSecretScanningAlerts(ctx, rc.RepoIDByName, rc.SecretScanningAlerts) },
		},
	} {
		if err := job.run(); err != nil {
			rc.Errors = append(rc.Errors, fmt.Sprintf("%s: %v", job.name, err))
		}
	}

	repoIDs := sortedRepoIDs(rc.SBOMByRepoID)
	for _, repoID := range repoIDs {
		if err := s.store.IngestSBOMMain(ctx, repoID, rc.SBOMByRepoID[repoID]); err != nil {
			rc.Errors = append(rc.Errors, fmt.Sprintf("sbom-main repo=%d: %v", repoID, err))
		}
	}
	return nil
}

type ingestLinksStage struct {
	store Store
}

func (s ingestLinksStage) Name() string { return "ingest-links" }

func (s ingestLinksStage) Run(ctx context.Context, rc *RunContext) error {
	if err := s.store.IngestDependabotAlertsLinks(ctx, rc.RepoIDByName, rc.DependabotAlerts); err != nil {
		rc.Errors = append(rc.Errors, fmt.Sprintf("dependabot-links: %v", err))
	}
	repoIDs := sortedRepoIDs(rc.SBOMByRepoID)
	for _, repoID := range repoIDs {
		if err := s.store.IngestSBOMLinks(ctx, repoID, rc.SBOMByRepoID[repoID]); err != nil {
			rc.Errors = append(rc.Errors, fmt.Sprintf("sbom-links repo=%d: %v", repoID, err))
		}
	}
	return nil
}

type deriveVulnerablePackagesStage struct {
	store Store
}

func (s deriveVulnerablePackagesStage) Name() string { return "derive-vulnerable-packages" }

func (s deriveVulnerablePackagesStage) Run(ctx context.Context, rc *RunContext) error {
	if err := s.store.RefreshVulnerableRepoPackages(ctx); err != nil {
		return err
	}
	return nil
}

type reportStage struct {
	store      Store
	outputPath string
}

func (s reportStage) Name() string { return "report" }

func (s reportStage) Run(ctx context.Context, rc *RunContext) error {
	reportData, err := s.store.QueryReportData(ctx)
	if err != nil {
		return fmt.Errorf("failed to query report: %w", err)
	}
	if err := exporter.WriteCSV(s.outputPath, reportData.Headers, reportData.Records); err != nil {
		return fmt.Errorf("failed to write csv report: %w", err)
	}
	return nil
}

func sortedRepoIDs(m map[int64]*gogithub.SBOM) []int64 {
	repoIDs := make([]int64, 0, len(m))
	for repoID := range m {
		repoIDs = append(repoIDs, repoID)
	}
	sort.Slice(repoIDs, func(i, j int) bool { return repoIDs[i] < repoIDs[j] })
	return repoIDs
}

func isRateLimitErr(err error) bool {
	var rl *gogithub.RateLimitError
	if errors.As(err, &rl) {
		return true
	}
	var abuse *gogithub.AbuseRateLimitError
	return errors.As(err, &abuse)
}
