package main

import (
	"context"
	"database/sql"
	"log"

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
	client := githubclient.New(ctx, cfg.Token)

	db, err := sql.Open("sqlite", cfg.SQLitePath)
	if err != nil {
		log.Fatalf("failed to open sqlite db: %v", err)
	}
	defer db.Close()

	store := sqlite.New(db)
	runner := orchestrator.NewRunner(cfg, client, store)

	if err := runner.Bootstrap(ctx); err != nil {
		log.Fatal(err)
	}
	repos, err := runner.LoadRepos(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fetchResult := runner.FetchDatasets(ctx, repos)
	errorsSeen := runner.ExecuteWrites(ctx, fetchResult)
	if err := runner.ExportReport(ctx); err != nil {
		log.Fatal(err)
	}
	runner.Finalize(errorsSeen)
}
