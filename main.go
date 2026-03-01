package main

import (
	"context"
	"database/sql"
	"log"
	"time"

	githubclient "github.com/AlvinRoe/orginv/internal/clients/github"
	"github.com/AlvinRoe/orginv/internal/config"
	"github.com/AlvinRoe/orginv/internal/orchestrator"
	"github.com/AlvinRoe/orginv/internal/store/sqlite"
	_ "modernc.org/sqlite"
)

func main() {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	client := githubclient.New(ctx, cfg.Token, githubclient.Options{
		MaxRetries:      cfg.GitHubMaxRetries,
		BaseDelay:       time.Duration(cfg.GitHubRetryBaseDelay) * time.Millisecond,
		RepoPageWorkers: cfg.GitHubRepoPageWorkers,
	})

	db, err := sql.Open("sqlite", cfg.SQLitePath)
	if err != nil {
		log.Fatalf("failed to open sqlite db: %v", err)
	}
	defer db.Close()

	store := sqlite.New(db, cfg.ReportSQLPath)
	runner := orchestrator.NewRunner(cfg, client, store)

	errorsSeen, err := runner.Run(ctx)
	if err != nil {
		log.Fatal(err)
	}
	runner.Finalize(errorsSeen)
}
