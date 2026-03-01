package sqlite

import (
	"context"
	"database/sql"
	"log"

	"github.com/AlvinRoe/orginv/internal/store/sqlite/sqlbatch"
	gogithub "github.com/google/go-github/v82/github"
)

type Store struct {
	db            *sql.DB
	reportSQLPath string
}

type RepoIndex map[string]int64

const defaultReportSQLPath = "./internal/sql/default_report.sql"

var defaultFlushOptions = sqlbatch.FlushOptions{
	MaxStatementsPerChunk: 500,
	MaxBytesPerChunk:      1 << 20,
}

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

func (s *Store) flushBatch(ctx context.Context, label string, batch *sqlbatch.Batch) error {
	if batch == nil || batch.Empty() {
		log.Printf("%s batch is empty", label)
		return nil
	}
	log.Printf("%s batch: tables=%d statements=%d bytes=%d", label, len(batch.Tables()), batch.TotalStatementCount(), batch.TotalByteSize())

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := batch.FlushInOrder(ctx, tx, defaultFlushOptions); err != nil {
		return err
	}
	return tx.Commit()
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
