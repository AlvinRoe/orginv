package sqlite

import (
	"context"
	"database/sql"

	gogithub "github.com/google/go-github/v82/github"
)

type Store struct {
	db *sql.DB
}

type RepoIndex map[string]int64

func New(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) DB() *sql.DB {
	return s.db
}

func (s *Store) InitSchema(ctx context.Context) error {
	_ = ctx
	return initSQLite(s.db)
}

func (s *Store) UpsertRepos(ctx context.Context, org string, repos []*gogithub.Repository) (RepoIndex, []*gogithub.Repository, error) {
	_ = ctx
	repoIDByName := make(RepoIndex, len(repos)*2)
	activeRepos := make([]*gogithub.Repository, 0, len(repos))

	for _, repo := range repos {
		if isIgnoredRepoName(repo.GetName()) {
			continue
		}
		repoID := repo.GetID()
		if err := upsertRepo(s.db, org, repo); err != nil {
			return nil, nil, err
		}
		repoIDByName[repo.GetFullName()] = repoID
		repoIDByName[repo.GetName()] = repoID
		repoIDByName[repoIDKey(repoID)] = repoID
		if !repo.GetArchived() && !repo.GetDisabled() {
			activeRepos = append(activeRepos, repo)
		}
	}

	return repoIDByName, activeRepos, nil
}

func (s *Store) IngestSBOM(ctx context.Context, repoID int64, sbom *gogithub.SBOM) error {
	_ = ctx
	return ingestSBOM(s.db, repoID, sbom)
}

func (s *Store) IngestDependabotAlerts(ctx context.Context, repoIDByName RepoIndex, alerts []*gogithub.DependabotAlert) error {
	_ = ctx
	return ingestDependabotAlerts(s.db, repoIDByName, alerts)
}

func (s *Store) IngestCodeScanningAlerts(ctx context.Context, repoIDByName RepoIndex, alerts []*gogithub.Alert) error {
	_ = ctx
	return ingestCodeScanningAlerts(s.db, repoIDByName, alerts)
}

func (s *Store) IngestSecretScanningAlerts(ctx context.Context, repoIDByName RepoIndex, alerts []*gogithub.SecretScanningAlert) error {
	_ = ctx
	return ingestSecretScanningAlerts(s.db, repoIDByName, alerts)
}

func (s *Store) ExportCSVReport(ctx context.Context, outputPath string) error {
	_ = ctx
	return exportCSVReport(s.db, outputPath)
}
