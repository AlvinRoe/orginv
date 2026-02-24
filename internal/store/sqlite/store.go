package sqlite

import (
	"context"
	"database/sql"

	gogithub "github.com/google/go-github/v82/github"
)

type Store struct {
	db            *sql.DB
	reportSQLPath string
}

type RepoIndex map[string]int64

const defaultReportSQLPath = "./internal/sql/default_report.sql"

func New(db *sql.DB, reportSQLPath string) *Store {
	if reportSQLPath == "" {
		reportSQLPath = defaultReportSQLPath
	}
	return &Store{
		db:            db,
		reportSQLPath: reportSQLPath,
	}
}

func (s *Store) DB() *sql.DB {
	return s.db
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
