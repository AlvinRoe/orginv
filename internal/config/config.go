package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	Org                   string
	Token                 string
	ResultsPerPage        int
	SQLitePath            string
	CSVOutputPath         string
	ReportSQLPath         string
	SBOMWorkers           int
	GitHubMaxRetries      int
	GitHubRetryBaseDelay  int
	GitHubRepoPageWorkers int
}

func LoadFromEnv() (Config, error) {
	org := os.Getenv("GITHUB_ORG")
	if org == "" {
		return Config{}, fmt.Errorf("GITHUB_ORG environment variable is not set")
	}

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return Config{}, fmt.Errorf("GITHUB_TOKEN environment variable is not set")
	}

	perPage := 100
	if perEnv := os.Getenv("RESULTS_PER_PAGE"); perEnv != "" {
		pp, err := strconv.Atoi(perEnv)
		if err != nil || pp <= 0 || pp > 100 {
			return Config{}, fmt.Errorf("invalid RESULTS_PER_PAGE: %s", perEnv)
		}
		perPage = pp
	}

	sqlitePath := os.Getenv("SQLITE_PATH")
	if sqlitePath == "" {
		sqlitePath = "./orginv.db"
	}

	csvPath := os.Getenv("CSV_OUTPUT_PATH")
	if csvPath == "" {
		csvPath = "./orginv-report.csv"
	}

	reportSQLPath := os.Getenv("REPORT_SQL_PATH")
	if reportSQLPath == "" {
		reportSQLPath = "./internal/sql/default_report.sql"
	}

	sbomWorkers := 10
	if sbomWorkersEnv := os.Getenv("SBOM_WORKERS"); sbomWorkersEnv != "" {
		v, err := strconv.Atoi(sbomWorkersEnv)
		if err != nil || v <= 0 || v > 100 {
			return Config{}, fmt.Errorf("invalid SBOM_WORKERS: %s", sbomWorkersEnv)
		}
		sbomWorkers = v
	}

	gitHubMaxRetries := 5
	if maxRetriesEnv := os.Getenv("GITHUB_MAX_RETRIES"); maxRetriesEnv != "" {
		v, err := strconv.Atoi(maxRetriesEnv)
		if err != nil || v < 0 || v > 20 {
			return Config{}, fmt.Errorf("invalid GITHUB_MAX_RETRIES: %s", maxRetriesEnv)
		}
		gitHubMaxRetries = v
	}

	gitHubRetryBaseDelayMS := 1000
	if baseDelayEnv := os.Getenv("GITHUB_RETRY_BASE_DELAY_MS"); baseDelayEnv != "" {
		v, err := strconv.Atoi(baseDelayEnv)
		if err != nil || v < 100 || v > 60000 {
			return Config{}, fmt.Errorf("invalid GITHUB_RETRY_BASE_DELAY_MS: %s", baseDelayEnv)
		}
		gitHubRetryBaseDelayMS = v
	}

	gitHubRepoPageWorkers := 4
	if repoPageWorkersEnv := os.Getenv("GITHUB_REPO_PAGE_WORKERS"); repoPageWorkersEnv != "" {
		v, err := strconv.Atoi(repoPageWorkersEnv)
		if err != nil || v <= 0 || v > 50 {
			return Config{}, fmt.Errorf("invalid GITHUB_REPO_PAGE_WORKERS: %s", repoPageWorkersEnv)
		}
		gitHubRepoPageWorkers = v
	}

	return Config{
		Org:                   org,
		Token:                 token,
		ResultsPerPage:        perPage,
		SQLitePath:            sqlitePath,
		CSVOutputPath:         csvPath,
		ReportSQLPath:         reportSQLPath,
		SBOMWorkers:           sbomWorkers,
		GitHubMaxRetries:      gitHubMaxRetries,
		GitHubRetryBaseDelay:  gitHubRetryBaseDelayMS,
		GitHubRepoPageWorkers: gitHubRepoPageWorkers,
	}, nil
}
