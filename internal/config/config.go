package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	Org            string
	Token          string
	ResultsPerPage int
	SQLitePath     string
	CSVOutputPath  string
	ReportSQLPath  string
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

	return Config{
		Org:            org,
		Token:          token,
		ResultsPerPage: perPage,
		SQLitePath:     sqlitePath,
		CSVOutputPath:  csvPath,
		ReportSQLPath:  reportSQLPath,
	}, nil
}
