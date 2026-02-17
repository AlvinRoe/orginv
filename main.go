package main

import (
	"context"
	"database/sql"
	"encoding/csv"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/go-github/v82/github"
	"golang.org/x/oauth2"
	_ "modernc.org/sqlite"
)

type retryRoundTripper struct {
	transport  http.RoundTripper
	maxRetries int
	baseDelay  time.Duration
}

type config struct {
	Org            string
	Token          string
	ResultsPerPage int
	SQLitePath     string
	CSVOutputPath  string
}

type dbWriteOp struct {
	name     string
	priority int
	rows     int
	apply    func(*sql.DB) error
}

type schemaColumn struct {
	name       string
	definition string
}

type codeScanningInstanceSnapshot struct {
	ref             string
	commitSHA       string
	path            string
	startLine       interface{}
	endLine         interface{}
	startColumn     interface{}
	endColumn       interface{}
	state           string
	category        string
	classifications string
}

func (r *retryRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error

	for attempt := 0; attempt <= r.maxRetries; attempt++ {
		resp, err = r.transport.RoundTrip(req)
		if err != nil {
			if attempt < r.maxRetries {
				time.Sleep(r.baseDelay * time.Duration(1<<attempt))
				continue
			}
			return nil, err
		}

		if resp.StatusCode >= 500 || resp.StatusCode == 429 {
			if attempt < r.maxRetries {
				resp.Body.Close()
				delay := r.baseDelay * time.Duration(1<<attempt)
				if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
					if seconds, parseErr := strconv.Atoi(retryAfter); parseErr == nil {
						delay = time.Duration(seconds) * time.Second
					}
				}
				log.Printf("Retrying request (attempt %d/%d) after %v: %s %s", attempt+1, r.maxRetries, delay, req.Method, req.URL)
				time.Sleep(delay)
				continue
			}
		}

		return resp, nil
	}

	return resp, err
}

func main() {
	cfg := loadConfig()
	ctx := context.Background()

	client := newGitHubClient(ctx, cfg.Token)
	db, err := sql.Open("sqlite", cfg.SQLitePath)
	if err != nil {
		log.Fatalf("failed to open sqlite db: %v", err)
	}
	defer db.Close()

	if err := initSQLite(db); err != nil {
		log.Fatalf("failed to initialize sqlite schema: %v", err)
	}

	runUUID := fmt.Sprintf("run-%d", time.Now().UTC().UnixNano())
	if err := startIngestionRun(db, runUUID); err != nil {
		log.Fatalf("failed to create ingestion run: %v", err)
	}

	var runErr error
	defer func() {
		status := "success"
		summary := ""
		if runErr != nil {
			status = "partial_success"
			summary = runErr.Error()
		}
		if err := finishIngestionRun(db, runUUID, status, summary); err != nil {
			log.Printf("failed to finalize ingestion run: %v", err)
		}
	}()

	repos, err := fetchAllRepos(ctx, client, cfg.Org, cfg.ResultsPerPage)
	if err != nil {
		log.Fatalf("failed to fetch repositories: %v", err)
	}
	log.Printf("found %d repos", len(repos))

	repoIDByName := make(map[string]int64, len(repos)*2)
	activeRepos := make([]*github.Repository, 0, len(repos))

	for _, repo := range repos {
		repoID := repo.GetID()
		if err := upsertRepo(db, runUUID, cfg.Org, repo); err != nil {
			log.Printf("failed to upsert repo %s: %v", repo.GetFullName(), err)
			continue
		}
		repoIDByName[repo.GetFullName()] = repoID
		repoIDByName[repo.GetName()] = repoID
		if !repo.GetArchived() && !repo.GetDisabled() {
			activeRepos = append(activeRepos, repo)
		}
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
				alerts, pages, err := fetchDependabotAlerts(ctx, client, cfg.Org, cfg.ResultsPerPage)
				if err != nil {
					return err
				}
				log.Printf("dependabot fetch complete: pages=%d alerts=%d", pages, len(alerts))
				enqueueWriteOp(dbWriteOp{
					name:     "dependabot alerts",
					priority: 30,
					rows:     len(alerts),
					apply: func(execDB *sql.DB) error {
						return ingestDependabotAlerts(execDB, runUUID, repoIDByName, alerts)
					},
				})
				return nil
			},
		},
		{
			name: "code scanning",
			run: func() error {
				alerts, pages, err := fetchCodeScanningAlerts(ctx, client, cfg.Org, cfg.ResultsPerPage)
				if err != nil {
					return err
				}
				log.Printf("code scanning fetch complete: pages=%d alerts=%d", pages, len(alerts))
				enqueueWriteOp(dbWriteOp{
					name:     "code scanning alerts",
					priority: 30,
					rows:     len(alerts),
					apply: func(execDB *sql.DB) error {
						return ingestCodeScanningAlerts(execDB, runUUID, repoIDByName, alerts)
					},
				})
				return nil
			},
		},
		{
			name: "secret scanning",
			run: func() error {
				alerts, pages, err := fetchSecretScanningAlerts(ctx, client, cfg.Org, cfg.ResultsPerPage)
				if err != nil {
					return err
				}
				log.Printf("secret scanning fetch complete: pages=%d alerts=%d", pages, len(alerts))
				enqueueWriteOp(dbWriteOp{
					name:     "secret scanning alerts",
					priority: 30,
					rows:     len(alerts),
					apply: func(execDB *sql.DB) error {
						return ingestSecretScanningAlerts(execDB, runUUID, repoIDByName, alerts)
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

	log.Printf("fetching per-repo datasets (sbom, rulesets)")
	const repoWorkers = 10
	repoChan := make(chan *github.Repository, len(activeRepos))
	var wg sync.WaitGroup

	for i := 0; i < repoWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for repo := range repoChan {
				repoName := repo.GetName()
				repoID := repo.GetID()
				repoStart := time.Now()
				log.Printf("worker %d fetch started for repo %s", workerID, repoName)

				sbom, _, sbomErr := client.DependencyGraph.GetSBOM(ctx, cfg.Org, repoName)
				if sbomErr != nil {
					recordErr(fmt.Sprintf("worker %d sbom %s", workerID, repoName), sbomErr)
				} else {
					enqueueWriteOp(dbWriteOp{
						name:     fmt.Sprintf("sbom %s", repoName),
						priority: 10,
						rows:     1,
						apply: func(execDB *sql.DB) error {
							return ingestSBOM(execDB, runUUID, repoID, sbom)
						},
					})
				}

				rulesets, pages, rErr := fetchRepoRulesets(ctx, client, cfg.Org, repoName, cfg.ResultsPerPage)
				if rErr != nil {
					recordErr(fmt.Sprintf("worker %d rulesets %s", workerID, repoName), rErr)
				} else {
					log.Printf("worker %d rulesets fetched for %s: pages=%d rulesets=%d", workerID, repoName, pages, len(rulesets))
					enqueueWriteOp(dbWriteOp{
						name:     fmt.Sprintf("rulesets %s", repoName),
						priority: 20,
						rows:     len(rulesets),
						apply: func(execDB *sql.DB) error {
							return ingestRepoRulesets(execDB, runUUID, repoID, rulesets)
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
	wg.Wait()
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
		if err := op.apply(db); err != nil {
			recordErr(fmt.Sprintf("db write failed: %s", op.name), err)
			continue
		}
		log.Printf("db queue %d/%d done: %s in %s", idx+1, len(writeOps), op.name, time.Since(started))
	}

	if err := exportCSVReport(db, runUUID, cfg.CSVOutputPath); err != nil {
		runErr = fmt.Errorf("csv export failed: %w", err)
		log.Fatalf("failed to export csv report: %v", err)
	}

	if len(errorsSeen) > 0 {
		runErr = fmt.Errorf("completed with %d ingestion errors (see logs)", len(errorsSeen))
	}

	log.Printf("phase 1 complete")
	log.Printf("sqlite output: %s", cfg.SQLitePath)
	log.Printf("csv output: %s", cfg.CSVOutputPath)
}

func loadConfig() config {
	org := os.Getenv("GITHUB_ORG")
	if org == "" {
		log.Fatal("GITHUB_ORG environment variable is not set")
	}
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		log.Fatal("GITHUB_TOKEN environment variable is not set")
	}

	perPage := 100
	if perEnv := os.Getenv("RESULTS_PER_PAGE"); perEnv != "" {
		pp, err := strconv.Atoi(perEnv)
		if err != nil || pp <= 0 || pp > 100 {
			log.Fatalf("invalid RESULTS_PER_PAGE: %s", perEnv)
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

	return config{
		Org:            org,
		Token:          token,
		ResultsPerPage: perPage,
		SQLitePath:     sqlitePath,
		CSVOutputPath:  csvPath,
	}
}

func newGitHubClient(ctx context.Context, token string) *github.Client {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	oauthClient := oauth2.NewClient(ctx, ts)
	retryClient := &http.Client{
		Transport: &retryRoundTripper{
			transport:  oauthClient.Transport,
			maxRetries: 3,
			baseDelay:  1 * time.Second,
		},
		Timeout: oauthClient.Timeout,
	}
	return github.NewClient(retryClient)
}

func initSQLite(db *sql.DB) error {
	schema := []string{
		`PRAGMA foreign_keys = ON;`,
		`PRAGMA journal_mode = WAL;`,
		`CREATE TABLE IF NOT EXISTS ingestion_runs (
			run_uuid TEXT PRIMARY KEY,
			started_at TEXT NOT NULL,
			finished_at TEXT,
			status TEXT,
			error_summary TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS repos (
			run_uuid TEXT NOT NULL,
			repo_id INTEGER NOT NULL,
			org_login TEXT NOT NULL,
			name TEXT NOT NULL,
			full_name TEXT NOT NULL,
			visibility TEXT,
			private INTEGER NOT NULL,
			archived INTEGER NOT NULL,
			disabled INTEGER NOT NULL,
			default_branch TEXT,
			language TEXT,
			open_issues_count INTEGER,
			description TEXT,
			homepage TEXT,
			topics TEXT,
			size_kb INTEGER,
			forks_count INTEGER,
			stargazers_count INTEGER,
			has_issues INTEGER,
			has_projects INTEGER,
			has_wiki INTEGER,
			has_pages INTEGER,
			has_discussions INTEGER,
			is_fork INTEGER,
			is_template INTEGER,
			license_spdx_id TEXT,
			advanced_security_status TEXT,
			secret_scanning_status TEXT,
			secret_scanning_push_protection_status TEXT,
			dependabot_security_updates_status TEXT,
			created_at TEXT,
			updated_at TEXT,
			pushed_at TEXT,
			PRIMARY KEY (run_uuid, repo_id)
		);`,
		`CREATE TABLE IF NOT EXISTS dependencies (
			dependency_id INTEGER PRIMARY KEY AUTOINCREMENT,
			ecosystem TEXT NOT NULL DEFAULT '',
			name TEXT NOT NULL DEFAULT '',
			version TEXT NOT NULL DEFAULT '',
			purl TEXT NOT NULL DEFAULT '',
			license TEXT,
			supplier TEXT,
			UNIQUE (ecosystem, name, version, purl)
		);`,
		`CREATE TABLE IF NOT EXISTS repo_dependencies (
			run_uuid TEXT NOT NULL,
			repo_id INTEGER NOT NULL,
			dependency_id INTEGER NOT NULL,
			source TEXT NOT NULL,
			snapshot_at TEXT NOT NULL,
			PRIMARY KEY (run_uuid, repo_id, dependency_id, source),
			FOREIGN KEY(dependency_id) REFERENCES dependencies(dependency_id)
		);`,
		`CREATE TABLE IF NOT EXISTS sbom_documents (
			sbom_id INTEGER PRIMARY KEY AUTOINCREMENT,
			run_uuid TEXT NOT NULL,
			repo_id INTEGER NOT NULL,
			spdx_id TEXT,
			spdx_version TEXT,
			document_name TEXT,
			data_license TEXT,
			document_namespace TEXT,
			generated_at TEXT,
			creation_creators TEXT,
			document_describes_count INTEGER,
			package_count INTEGER,
			relationship_count INTEGER,
			UNIQUE (run_uuid, repo_id)
		);`,
		`CREATE TABLE IF NOT EXISTS sbom_relationships (
			run_uuid TEXT NOT NULL,
			sbom_id INTEGER NOT NULL,
			from_dependency_id INTEGER,
			to_dependency_id INTEGER,
			relationship_type TEXT NOT NULL,
			PRIMARY KEY (run_uuid, sbom_id, from_dependency_id, to_dependency_id, relationship_type),
			FOREIGN KEY(sbom_id) REFERENCES sbom_documents(sbom_id),
			FOREIGN KEY(from_dependency_id) REFERENCES dependencies(dependency_id),
			FOREIGN KEY(to_dependency_id) REFERENCES dependencies(dependency_id)
		);`,
		`CREATE TABLE IF NOT EXISTS dependabot_alerts (
			run_uuid TEXT NOT NULL,
			repo_id INTEGER NOT NULL,
			alert_number INTEGER NOT NULL,
			state TEXT,
			severity TEXT,
			ecosystem TEXT,
			package_name TEXT,
			manifest_path TEXT,
			created_at TEXT,
			updated_at TEXT,
			fixed_at TEXT,
			dismissed_reason TEXT,
			dependency_id INTEGER,
			PRIMARY KEY (run_uuid, repo_id, alert_number),
			FOREIGN KEY(dependency_id) REFERENCES dependencies(dependency_id)
		);`,
		`CREATE TABLE IF NOT EXISTS code_scanning_alerts (
			run_uuid TEXT NOT NULL,
			repo_id INTEGER NOT NULL,
			alert_number INTEGER NOT NULL,
			state TEXT,
			rule_id TEXT,
			tool TEXT,
			severity TEXT,
			security_severity TEXT,
			created_at TEXT,
			fixed_at TEXT,
			most_recent_ref TEXT,
			most_recent_commit_sha TEXT,
			most_recent_path TEXT,
			most_recent_start_line INTEGER,
			most_recent_end_line INTEGER,
			most_recent_start_column INTEGER,
			most_recent_end_column INTEGER,
			most_recent_state TEXT,
			most_recent_category TEXT,
			most_recent_classifications TEXT,
			PRIMARY KEY (run_uuid, repo_id, alert_number)
		);`,
		`CREATE TABLE IF NOT EXISTS secret_scanning_alerts (
			run_uuid TEXT NOT NULL,
			repo_id INTEGER NOT NULL,
			alert_number INTEGER NOT NULL,
			state TEXT,
			secret_type TEXT,
			resolution TEXT,
			created_at TEXT,
			updated_at TEXT,
			resolved_at TEXT,
			PRIMARY KEY (run_uuid, repo_id, alert_number)
		);`,
		`CREATE TABLE IF NOT EXISTS repo_rulesets (
			run_uuid TEXT NOT NULL,
			repo_id INTEGER NOT NULL,
			ruleset_id INTEGER NOT NULL,
			name TEXT,
			enforcement TEXT,
			target TEXT,
			source TEXT,
			source_type TEXT,
			bypass_actor_count INTEGER,
			current_user_can_bypass TEXT,
			node_id TEXT,
			created_at TEXT,
			updated_at TEXT,
			ref_name_includes TEXT,
			ref_name_excludes TEXT,
			PRIMARY KEY (run_uuid, repo_id, ruleset_id)
		);`,
	}

	for _, stmt := range schema {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return applySchemaMigrations(db)
}

func applySchemaMigrations(db *sql.DB) error {
	migrations := map[string][]schemaColumn{
		"repos": {
			{name: "description", definition: "TEXT"},
			{name: "homepage", definition: "TEXT"},
			{name: "topics", definition: "TEXT"},
			{name: "size_kb", definition: "INTEGER"},
			{name: "forks_count", definition: "INTEGER"},
			{name: "stargazers_count", definition: "INTEGER"},
			{name: "has_issues", definition: "INTEGER"},
			{name: "has_projects", definition: "INTEGER"},
			{name: "has_wiki", definition: "INTEGER"},
			{name: "has_pages", definition: "INTEGER"},
			{name: "has_discussions", definition: "INTEGER"},
			{name: "is_fork", definition: "INTEGER"},
			{name: "is_template", definition: "INTEGER"},
			{name: "license_spdx_id", definition: "TEXT"},
			{name: "advanced_security_status", definition: "TEXT"},
			{name: "secret_scanning_status", definition: "TEXT"},
			{name: "secret_scanning_push_protection_status", definition: "TEXT"},
			{name: "dependabot_security_updates_status", definition: "TEXT"},
		},
		"sbom_documents": {
			{name: "spdx_id", definition: "TEXT"},
			{name: "document_name", definition: "TEXT"},
			{name: "data_license", definition: "TEXT"},
			{name: "document_namespace", definition: "TEXT"},
			{name: "creation_creators", definition: "TEXT"},
			{name: "document_describes_count", definition: "INTEGER"},
			{name: "package_count", definition: "INTEGER"},
			{name: "relationship_count", definition: "INTEGER"},
		},
		"code_scanning_alerts": {
			{name: "most_recent_ref", definition: "TEXT"},
			{name: "most_recent_commit_sha", definition: "TEXT"},
			{name: "most_recent_path", definition: "TEXT"},
			{name: "most_recent_start_line", definition: "INTEGER"},
			{name: "most_recent_end_line", definition: "INTEGER"},
			{name: "most_recent_start_column", definition: "INTEGER"},
			{name: "most_recent_end_column", definition: "INTEGER"},
			{name: "most_recent_state", definition: "TEXT"},
			{name: "most_recent_category", definition: "TEXT"},
			{name: "most_recent_classifications", definition: "TEXT"},
		},
		"repo_rulesets": {
			{name: "name", definition: "TEXT"},
			{name: "source", definition: "TEXT"},
			{name: "source_type", definition: "TEXT"},
			{name: "bypass_actor_count", definition: "INTEGER"},
			{name: "current_user_can_bypass", definition: "TEXT"},
			{name: "node_id", definition: "TEXT"},
			{name: "created_at", definition: "TEXT"},
			{name: "updated_at", definition: "TEXT"},
			{name: "ref_name_includes", definition: "TEXT"},
			{name: "ref_name_excludes", definition: "TEXT"},
		},
	}

	for table, cols := range migrations {
		if err := ensureColumns(db, table, cols); err != nil {
			return err
		}
	}
	return nil
}

func ensureColumns(db *sql.DB, table string, cols []schemaColumn) error {
	existing, err := tableColumns(db, table)
	if err != nil {
		return err
	}
	for _, col := range cols {
		if _, ok := existing[col.name]; ok {
			continue
		}
		stmt := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, col.name, col.definition)
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("failed adding column %s.%s: %w", table, col.name, err)
		}
	}
	return nil
}

func tableColumns(db *sql.DB, table string) (map[string]struct{}, error) {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols := make(map[string]struct{})
	for rows.Next() {
		var cid int
		var name string
		var colType string
		var notNull int
		var defaultValue interface{}
		var pk int
		if err := rows.Scan(&cid, &name, &colType, &notNull, &defaultValue, &pk); err != nil {
			return nil, err
		}
		cols[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return cols, nil
}

func startIngestionRun(db *sql.DB, runUUID string) error {
	_, err := db.Exec(`INSERT INTO ingestion_runs(run_uuid, started_at, status) VALUES (?, ?, ?)`, runUUID, time.Now().UTC().Format(time.RFC3339), "running")
	return err
}

func finishIngestionRun(db *sql.DB, runUUID, status, summary string) error {
	_, err := db.Exec(`UPDATE ingestion_runs SET finished_at = ?, status = ?, error_summary = ? WHERE run_uuid = ?`, time.Now().UTC().Format(time.RFC3339), status, summary, runUUID)
	return err
}

func upsertRepo(db *sql.DB, runUUID, org string, repo *github.Repository) error {
	topics := strings.Join(repo.Topics, ",")
	licenseSPDX := ""
	if repo.License != nil {
		licenseSPDX = repo.License.GetSPDXID()
	}
	advancedSecurityStatus := ""
	secretScanningStatus := ""
	secretScanningPushProtectionStatus := ""
	dependabotSecurityUpdatesStatus := ""
	if repo.SecurityAndAnalysis != nil {
		if repo.SecurityAndAnalysis.AdvancedSecurity != nil {
			advancedSecurityStatus = repo.SecurityAndAnalysis.AdvancedSecurity.GetStatus()
		}
		if repo.SecurityAndAnalysis.SecretScanning != nil {
			secretScanningStatus = repo.SecurityAndAnalysis.SecretScanning.GetStatus()
		}
		if repo.SecurityAndAnalysis.SecretScanningPushProtection != nil {
			secretScanningPushProtectionStatus = repo.SecurityAndAnalysis.SecretScanningPushProtection.GetStatus()
		}
		if repo.SecurityAndAnalysis.DependabotSecurityUpdates != nil {
			dependabotSecurityUpdatesStatus = repo.SecurityAndAnalysis.DependabotSecurityUpdates.GetStatus()
		}
	}

	_, err := db.Exec(`
		INSERT INTO repos(
			run_uuid, repo_id, org_login, name, full_name, visibility, private, archived, disabled,
			default_branch, language, open_issues_count, description, homepage, topics,
			size_kb, forks_count, stargazers_count, has_issues, has_projects, has_wiki, has_pages,
			has_discussions, is_fork, is_template, license_spdx_id, advanced_security_status,
			secret_scanning_status, secret_scanning_push_protection_status, dependabot_security_updates_status,
			created_at, updated_at, pushed_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(run_uuid, repo_id) DO UPDATE SET
			org_login = excluded.org_login,
			name = excluded.name,
			full_name = excluded.full_name,
			visibility = excluded.visibility,
			private = excluded.private,
			archived = excluded.archived,
			disabled = excluded.disabled,
			default_branch = excluded.default_branch,
			language = excluded.language,
			open_issues_count = excluded.open_issues_count,
			description = excluded.description,
			homepage = excluded.homepage,
			topics = excluded.topics,
			size_kb = excluded.size_kb,
			forks_count = excluded.forks_count,
			stargazers_count = excluded.stargazers_count,
			has_issues = excluded.has_issues,
			has_projects = excluded.has_projects,
			has_wiki = excluded.has_wiki,
			has_pages = excluded.has_pages,
			has_discussions = excluded.has_discussions,
			is_fork = excluded.is_fork,
			is_template = excluded.is_template,
			license_spdx_id = excluded.license_spdx_id,
			advanced_security_status = excluded.advanced_security_status,
			secret_scanning_status = excluded.secret_scanning_status,
			secret_scanning_push_protection_status = excluded.secret_scanning_push_protection_status,
			dependabot_security_updates_status = excluded.dependabot_security_updates_status,
			created_at = excluded.created_at,
			updated_at = excluded.updated_at,
			pushed_at = excluded.pushed_at
	`,
		runUUID,
		repo.GetID(),
		org,
		repo.GetName(),
		repo.GetFullName(),
		repo.GetVisibility(),
		boolToInt(repo.GetPrivate()),
		boolToInt(repo.GetArchived()),
		boolToInt(repo.GetDisabled()),
		repo.GetDefaultBranch(),
		repo.GetLanguage(),
		repo.GetOpenIssuesCount(),
		repo.GetDescription(),
		repo.GetHomepage(),
		topics,
		repo.GetSize(),
		repo.GetForksCount(),
		repo.GetStargazersCount(),
		boolToInt(repo.GetHasIssues()),
		boolToInt(repo.GetHasProjects()),
		boolToInt(repo.GetHasWiki()),
		boolToInt(repo.GetHasPages()),
		boolToInt(repo.GetHasDiscussions()),
		boolToInt(repo.GetFork()),
		boolToInt(repo.GetIsTemplate()),
		licenseSPDX,
		advancedSecurityStatus,
		secretScanningStatus,
		secretScanningPushProtectionStatus,
		dependabotSecurityUpdatesStatus,
		formatGitHubTimePtr(repo.CreatedAt),
		formatGitHubTimePtr(repo.UpdatedAt),
		formatGitHubTimePtr(repo.PushedAt),
	)
	return err
}

func fetchAllRepos(ctx context.Context, client *github.Client, org string, perPage int) ([]*github.Repository, error) {
	opt := &github.RepositoryListByOrgOptions{
		Type:        "all",
		ListOptions: github.ListOptions{PerPage: perPage, Page: 1},
	}
	firstPageRepos, resp, err := client.Repositories.ListByOrg(ctx, org, opt)
	if err != nil {
		return nil, err
	}

	allRepos := make([]*github.Repository, 0, len(firstPageRepos))
	allRepos = append(allRepos, firstPageRepos...)
	if resp.LastPage <= 1 {
		return allRepos, nil
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	for page := 2; page <= resp.LastPage; page++ {
		wg.Add(1)
		go func(pageNum int) {
			defer wg.Done()
			pageOpt := &github.RepositoryListByOrgOptions{
				Type:        "all",
				ListOptions: github.ListOptions{PerPage: perPage, Page: pageNum},
			}
			repos, _, pErr := client.Repositories.ListByOrg(ctx, org, pageOpt)
			if pErr != nil {
				log.Printf("failed to list repos page %d: %v", pageNum, pErr)
				return
			}
			mu.Lock()
			allRepos = append(allRepos, repos...)
			mu.Unlock()
		}(page)
	}
	wg.Wait()
	return allRepos, nil
}

func ingestSBOM(db *sql.DB, runUUID string, repoID int64, sbom *github.SBOM) error {
	if sbom == nil || sbom.SBOM == nil {
		return nil
	}
	doc := sbom.SBOM

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec(`
		INSERT INTO sbom_documents(
			run_uuid, repo_id, spdx_id, spdx_version, document_name, data_license,
			document_namespace, generated_at, creation_creators, document_describes_count, package_count, relationship_count
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(run_uuid, repo_id) DO UPDATE SET
			spdx_id = excluded.spdx_id,
			spdx_version = excluded.spdx_version,
			document_name = excluded.document_name,
			data_license = excluded.data_license,
			document_namespace = excluded.document_namespace,
			generated_at = excluded.generated_at,
			creation_creators = excluded.creation_creators,
			document_describes_count = excluded.document_describes_count,
			package_count = excluded.package_count,
			relationship_count = excluded.relationship_count
	`,
		runUUID,
		repoID,
		doc.GetSPDXID(),
		doc.GetSPDXVersion(),
		doc.GetName(),
		doc.GetDataLicense(),
		doc.GetDocumentNamespace(),
		sbomCreatedAt(doc),
		sbomCreators(doc),
		len(doc.DocumentDescribes),
		len(doc.Packages),
		len(doc.Relationships),
	)
	if err != nil {
		return err
	}

	var sbomID int64
	if err := tx.QueryRow(`SELECT sbom_id FROM sbom_documents WHERE run_uuid = ? AND repo_id = ?`, runUUID, repoID).Scan(&sbomID); err != nil {
		return err
	}

	pkgIDMap := make(map[string]int64, len(doc.Packages))
	for _, pkg := range doc.Packages {
		if pkg == nil {
			continue
		}
		purl := extractPURLFromDependency(pkg)
		ecosystem := ecosystemFromPURL(purl)
		if ecosystem == "" {
			ecosystem = "unknown"
		}
		depID, err := upsertDependencyTx(tx, ecosystem, pkg.GetName(), pkg.GetVersionInfo(), purl, pkg.GetLicenseConcluded(), "")
		if err != nil {
			return err
		}
		pkgIDMap[pkg.GetSPDXID()] = depID
		if _, err := tx.Exec(`
			INSERT OR IGNORE INTO repo_dependencies(run_uuid, repo_id, dependency_id, source, snapshot_at)
			VALUES (?, ?, ?, ?, ?)
		`, runUUID, repoID, depID, "sbom", time.Now().UTC().Format(time.RFC3339)); err != nil {
			return err
		}
	}

	for _, rel := range doc.Relationships {
		if rel == nil {
			continue
		}
		fromID, okFrom := pkgIDMap[rel.SPDXElementID]
		toID, okTo := pkgIDMap[rel.RelatedSPDXElement]
		if !okFrom && !okTo {
			continue
		}
		_, err := tx.Exec(`
			INSERT OR IGNORE INTO sbom_relationships(run_uuid, sbom_id, from_dependency_id, to_dependency_id, relationship_type)
			VALUES (?, ?, ?, ?, ?)
		`, runUUID, sbomID, nullableInt64(okFrom, fromID), nullableInt64(okTo, toID), rel.RelationshipType)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func upsertDependencyTx(tx *sql.Tx, ecosystem, name, version, purl, license, supplier string) (int64, error) {
	_, err := tx.Exec(`
		INSERT OR IGNORE INTO dependencies(ecosystem, name, version, purl, license, supplier)
		VALUES (?, ?, ?, ?, ?, ?)
	`, safeStr(ecosystem), safeStr(name), safeStr(version), safeStr(purl), license, supplier)
	if err != nil {
		return 0, err
	}

	var depID int64
	err = tx.QueryRow(`
		SELECT dependency_id FROM dependencies
		WHERE ecosystem = ? AND name = ? AND version = ? AND purl = ?
	`, safeStr(ecosystem), safeStr(name), safeStr(version), safeStr(purl)).Scan(&depID)
	if err != nil {
		return 0, err
	}
	return depID, nil
}

func fetchDependabotAlerts(ctx context.Context, client *github.Client, org string, perPage int) ([]*github.DependabotAlert, int, error) {
	all := make([]*github.DependabotAlert, 0)
	pageCount := 0
	seen := make(map[string]struct{})
	states := []string{"open", "dismissed", "fixed", "auto_dismissed"}
	for _, state := range states {
		page := 1
		for {
			opts := &github.ListAlertsOptions{
				State:       stringPtr(state),
				ListOptions: github.ListOptions{PerPage: perPage, Page: page},
			}
			alerts, resp, err := client.Dependabot.ListOrgAlerts(ctx, org, opts)
			if err != nil {
				return nil, pageCount, fmt.Errorf("dependabot org alerts fetch failed (org=%s state=%s page=%d): %w", org, state, page, err)
			}
			pageCount++
			added := 0
			for _, alert := range alerts {
				if alert == nil {
					continue
				}
				key := dependabotAlertKey(alert)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				all = append(all, alert)
				added++
			}
			log.Printf("dependabot page fetched: state=%s page=%d items=%d added=%d total=%d", state, page, len(alerts), added, len(all))
			if resp.NextPage == 0 {
				break
			}
			page = resp.NextPage
		}
	}
	return all, pageCount, nil
}

func ingestDependabotAlerts(db *sql.DB, runUUID string, repoIDByName map[string]int64, alerts []*github.DependabotAlert) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO dependabot_alerts(
			run_uuid, repo_id, alert_number, state, severity, ecosystem, package_name,
			manifest_path, created_at, updated_at, fixed_at, dismissed_reason, dependency_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(run_uuid, repo_id, alert_number) DO UPDATE SET
			state = excluded.state,
			severity = excluded.severity,
			ecosystem = excluded.ecosystem,
			package_name = excluded.package_name,
			manifest_path = excluded.manifest_path,
			created_at = excluded.created_at,
			updated_at = excluded.updated_at,
			fixed_at = excluded.fixed_at,
			dismissed_reason = excluded.dismissed_reason,
			dependency_id = excluded.dependency_id
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	inserted := 0
	skippedRepo := 0
	for _, a := range alerts {
		if a == nil {
			continue
		}
		repoID, ok := resolveAlertRepoID(repoIDByName, a.GetRepository())
		if !ok {
			skippedRepo++
			continue
		}
		dependency := a.GetDependency()
		securityVuln := a.GetSecurityVulnerability()
		securityAdv := a.GetSecurityAdvisory()

		depPackage := dependency.GetPackage()
		secPackage := securityVuln.GetPackage()
		ecosystem := firstNonEmpty(depPackage.GetEcosystem(), secPackage.GetEcosystem())
		pkgName := firstNonEmpty(depPackage.GetName(), secPackage.GetName())
		severity := strings.ToLower(firstNonEmpty(securityVuln.GetSeverity(), securityAdv.GetSeverity()))

		depIDPtr, depErr := lookupDependencyIDTx(tx, ecosystem, pkgName)
		if depErr != nil {
			return depErr
		}

		_, err := stmt.Exec(
			runUUID,
			repoID,
			a.GetNumber(),
			a.GetState(),
			severity,
			ecosystem,
			pkgName,
			dependency.GetManifestPath(),
			formatGitHubTimePtr(a.CreatedAt),
			formatGitHubTimePtr(a.UpdatedAt),
			formatGitHubTimePtr(a.FixedAt),
			a.GetDismissedReason(),
			depIDPtr,
		)
		if err != nil {
			return err
		}
		inserted++
	}
	log.Printf("dependabot ingest summary: total=%d inserted=%d skipped_repo=%d", len(alerts), inserted, skippedRepo)

	return tx.Commit()
}

func fetchCodeScanningAlerts(ctx context.Context, client *github.Client, org string, perPage int) ([]*github.Alert, int, error) {
	all := make([]*github.Alert, 0)
	pageCount := 0
	seen := make(map[string]struct{})
	states := []string{"open", "closed"}
	for _, state := range states {
		page := 1
		for {
			opts := &github.AlertListOptions{
				State:       state,
				ListOptions: github.ListOptions{PerPage: perPage, Page: page},
			}
			alerts, resp, err := client.CodeScanning.ListAlertsForOrg(ctx, org, opts)
			if err != nil {
				return nil, pageCount, fmt.Errorf("code scanning org alerts fetch failed (org=%s state=%s page=%d): %w", org, state, page, err)
			}
			pageCount++
			added := 0
			for _, alert := range alerts {
				if alert == nil {
					continue
				}
				key := codeScanningAlertKey(alert)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				all = append(all, alert)
				added++
			}
			log.Printf("code scanning page fetched: state=%s page=%d items=%d added=%d total=%d", state, page, len(alerts), added, len(all))
			if resp.NextPage == 0 {
				break
			}
			page = resp.NextPage
		}
	}
	return all, pageCount, nil
}

func ingestCodeScanningAlerts(db *sql.DB, runUUID string, repoIDByName map[string]int64, alerts []*github.Alert) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO code_scanning_alerts(
			run_uuid, repo_id, alert_number, state, rule_id, tool, severity,
			security_severity, created_at, fixed_at, most_recent_ref, most_recent_commit_sha,
			most_recent_path, most_recent_start_line, most_recent_end_line, most_recent_start_column,
			most_recent_end_column, most_recent_state, most_recent_category, most_recent_classifications
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(run_uuid, repo_id, alert_number) DO UPDATE SET
			state = excluded.state,
			rule_id = excluded.rule_id,
			tool = excluded.tool,
			severity = excluded.severity,
			security_severity = excluded.security_severity,
			created_at = excluded.created_at,
			fixed_at = excluded.fixed_at,
			most_recent_ref = excluded.most_recent_ref,
			most_recent_commit_sha = excluded.most_recent_commit_sha,
			most_recent_path = excluded.most_recent_path,
			most_recent_start_line = excluded.most_recent_start_line,
			most_recent_end_line = excluded.most_recent_end_line,
			most_recent_start_column = excluded.most_recent_start_column,
			most_recent_end_column = excluded.most_recent_end_column,
			most_recent_state = excluded.most_recent_state,
			most_recent_category = excluded.most_recent_category,
			most_recent_classifications = excluded.most_recent_classifications
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	inserted := 0
	skippedRepo := 0
	for _, a := range alerts {
		if a == nil {
			continue
		}
		repoID, ok := resolveAlertRepoID(repoIDByName, a.GetRepository())
		if !ok {
			skippedRepo++
			continue
		}
		toolName := ""
		if tool := a.GetTool(); tool != nil {
			toolName = tool.GetName()
		}
		ruleID := ""
		securitySeverity := ""
		if rule := a.GetRule(); rule != nil {
			ruleID = rule.GetID()
			securitySeverity = rule.GetSecuritySeverityLevel()
		}
		instance := snapshotCodeScanningInstance(a.GetMostRecentInstance())
		_, err := stmt.Exec(
			runUUID,
			repoID,
			a.GetNumber(),
			a.GetState(),
			ruleID,
			toolName,
			a.GetRuleSeverity(),
			securitySeverity,
			formatGitHubTimePtr(a.CreatedAt),
			formatGitHubTimePtr(a.FixedAt),
			instance.ref,
			instance.commitSHA,
			instance.path,
			instance.startLine,
			instance.endLine,
			instance.startColumn,
			instance.endColumn,
			instance.state,
			instance.category,
			instance.classifications,
		)
		if err != nil {
			return err
		}
		inserted++
	}
	log.Printf("code scanning ingest summary: total=%d inserted=%d skipped_repo=%d", len(alerts), inserted, skippedRepo)

	return tx.Commit()
}

func fetchSecretScanningAlerts(ctx context.Context, client *github.Client, org string, perPage int) ([]*github.SecretScanningAlert, int, error) {
	all := make([]*github.SecretScanningAlert, 0)
	pageCount := 0
	seen := make(map[string]struct{})
	states := []string{"open", "resolved"}
	for _, state := range states {
		page := 1
		for {
			opts := &github.SecretScanningAlertListOptions{
				State:       state,
				ListOptions: github.ListOptions{PerPage: perPage, Page: page},
			}
			alerts, resp, err := client.SecretScanning.ListAlertsForOrg(ctx, org, opts)
			if err != nil {
				return nil, pageCount, fmt.Errorf("secret scanning org alerts fetch failed (org=%s state=%s page=%d): %w", org, state, page, err)
			}
			pageCount++
			added := 0
			for _, alert := range alerts {
				if alert == nil {
					continue
				}
				key := secretScanningAlertKey(alert)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				all = append(all, alert)
				added++
			}
			log.Printf("secret scanning page fetched: state=%s page=%d items=%d added=%d total=%d", state, page, len(alerts), added, len(all))
			if resp.NextPage == 0 {
				break
			}
			page = resp.NextPage
		}
	}
	return all, pageCount, nil
}

func ingestSecretScanningAlerts(db *sql.DB, runUUID string, repoIDByName map[string]int64, alerts []*github.SecretScanningAlert) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO secret_scanning_alerts(
			run_uuid, repo_id, alert_number, state, secret_type, resolution, created_at, updated_at, resolved_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(run_uuid, repo_id, alert_number) DO UPDATE SET
			state = excluded.state,
			secret_type = excluded.secret_type,
			resolution = excluded.resolution,
			created_at = excluded.created_at,
			updated_at = excluded.updated_at,
			resolved_at = excluded.resolved_at
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	inserted := 0
	skippedRepo := 0
	for _, a := range alerts {
		if a == nil {
			continue
		}
		repoID, ok := resolveAlertRepoID(repoIDByName, a.GetRepository())
		if !ok {
			skippedRepo++
			continue
		}
		_, err := stmt.Exec(
			runUUID,
			repoID,
			a.GetNumber(),
			a.GetState(),
			a.GetSecretType(),
			a.GetResolution(),
			formatGitHubTimePtr(a.CreatedAt),
			formatGitHubTimePtr(a.UpdatedAt),
			formatGitHubTimePtr(a.ResolvedAt),
		)
		if err != nil {
			return err
		}
		inserted++
	}
	log.Printf("secret scanning ingest summary: total=%d inserted=%d skipped_repo=%d", len(alerts), inserted, skippedRepo)

	return tx.Commit()
}

func fetchRepoRulesets(ctx context.Context, client *github.Client, owner, repo string, perPage int) ([]*github.RepositoryRuleset, int, error) {
	all := make([]*github.RepositoryRuleset, 0)
	page := 1
	pageCount := 0
	includeParents := true
	for {
		opts := &github.RepositoryListRulesetsOptions{
			IncludesParents: &includeParents,
			ListOptions:     github.ListOptions{PerPage: perPage, Page: page},
		}
		rulesets, resp, err := client.Repositories.GetAllRulesets(ctx, owner, repo, opts)
		if err != nil {
			return nil, pageCount, err
		}
		pageCount++
		all = append(all, rulesets...)
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}
	return all, pageCount, nil
}

func ingestRepoRulesets(db *sql.DB, runUUID string, repoID int64, rulesets []*github.RepositoryRuleset) error {
	if len(rulesets) == 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO repo_rulesets(
			run_uuid, repo_id, ruleset_id, name, enforcement, target, source, source_type,
			bypass_actor_count, current_user_can_bypass, node_id, created_at, updated_at, ref_name_includes, ref_name_excludes
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(run_uuid, repo_id, ruleset_id) DO UPDATE SET
			name = excluded.name,
			enforcement = excluded.enforcement,
			target = excluded.target,
			source = excluded.source,
			source_type = excluded.source_type,
			bypass_actor_count = excluded.bypass_actor_count,
			current_user_can_bypass = excluded.current_user_can_bypass,
			node_id = excluded.node_id,
			created_at = excluded.created_at,
			updated_at = excluded.updated_at,
			ref_name_includes = excluded.ref_name_includes,
			ref_name_excludes = excluded.ref_name_excludes
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, rs := range rulesets {
		if rs == nil {
			continue
		}
		enforcement := string(rs.Enforcement)
		target := ""
		if t := rs.GetTarget(); t != nil {
			target = string(*t)
		}
		sourceType := ""
		if st := rs.SourceType; st != nil {
			sourceType = string(*st)
		}
		refNameIncludes := ""
		refNameExcludes := ""
		if rs.Conditions != nil && rs.Conditions.RefName != nil {
			refNameIncludes = strings.Join(rs.Conditions.RefName.Include, ",")
			refNameExcludes = strings.Join(rs.Conditions.RefName.Exclude, ",")
		}
		currentUserCanBypass := ""
		if rs.CurrentUserCanBypass != nil {
			currentUserCanBypass = string(*rs.CurrentUserCanBypass)
		}
		_, err = stmt.Exec(
			runUUID,
			repoID,
			rs.GetID(),
			rs.Name,
			enforcement,
			target,
			rs.Source,
			sourceType,
			len(rs.BypassActors),
			currentUserCanBypass,
			rs.GetNodeID(),
			formatGitHubTimePtr(rs.CreatedAt),
			formatGitHubTimePtr(rs.UpdatedAt),
			refNameIncludes,
			refNameExcludes,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func exportCSVReport(db *sql.DB, runUUID, outputPath string) error {
	query := `
		SELECT
			r.run_uuid,
			r.repo_id,
			r.org_login,
			r.name,
			r.full_name,
			r.visibility,
			r.private,
			r.archived,
			r.disabled,
				r.default_branch,
				r.language,
				r.open_issues_count,
				r.description,
				r.homepage,
				r.topics,
				r.size_kb,
				r.forks_count,
				r.stargazers_count,
				r.has_issues,
				r.has_projects,
				r.has_wiki,
				r.has_pages,
				r.has_discussions,
				r.is_fork,
				r.is_template,
				r.license_spdx_id,
				r.advanced_security_status,
				r.secret_scanning_status,
				r.secret_scanning_push_protection_status,
				r.dependabot_security_updates_status,
				r.created_at AS repo_created_at,
				r.updated_at AS repo_updated_at,
				r.pushed_at AS repo_pushed_at,
				(SELECT sd.spdx_id FROM sbom_documents sd WHERE sd.run_uuid = ? AND sd.repo_id = r.repo_id LIMIT 1) AS sbom_spdx_id,
				(SELECT sd.spdx_version FROM sbom_documents sd WHERE sd.run_uuid = ? AND sd.repo_id = r.repo_id LIMIT 1) AS sbom_spdx_version,
				(SELECT sd.document_name FROM sbom_documents sd WHERE sd.run_uuid = ? AND sd.repo_id = r.repo_id LIMIT 1) AS sbom_document_name,
				(SELECT sd.data_license FROM sbom_documents sd WHERE sd.run_uuid = ? AND sd.repo_id = r.repo_id LIMIT 1) AS sbom_data_license,
				(SELECT sd.document_namespace FROM sbom_documents sd WHERE sd.run_uuid = ? AND sd.repo_id = r.repo_id LIMIT 1) AS sbom_document_namespace,
				(SELECT sd.generated_at FROM sbom_documents sd WHERE sd.run_uuid = ? AND sd.repo_id = r.repo_id LIMIT 1) AS sbom_generated_at,
				(SELECT sd.creation_creators FROM sbom_documents sd WHERE sd.run_uuid = ? AND sd.repo_id = r.repo_id LIMIT 1) AS sbom_creation_creators,
				(SELECT sd.document_describes_count FROM sbom_documents sd WHERE sd.run_uuid = ? AND sd.repo_id = r.repo_id LIMIT 1) AS sbom_document_describes_count,
				(SELECT sd.package_count FROM sbom_documents sd WHERE sd.run_uuid = ? AND sd.repo_id = r.repo_id LIMIT 1) AS sbom_package_count,
				(SELECT sd.relationship_count FROM sbom_documents sd WHERE sd.run_uuid = ? AND sd.repo_id = r.repo_id LIMIT 1) AS sbom_relationship_count,
			(SELECT COUNT(1) FROM repo_dependencies rd WHERE rd.run_uuid = ? AND rd.repo_id = r.repo_id) AS dependency_count,
			(
				SELECT COALESCE(group_concat(
					'dependency_id=' || d.dependency_id ||
					';ecosystem=' || COALESCE(d.ecosystem, '') ||
					';name=' || COALESCE(d.name, '') ||
					';version=' || COALESCE(d.version, '') ||
					';purl=' || COALESCE(d.purl, '') ||
					';license=' || COALESCE(d.license, '') ||
					';supplier=' || COALESCE(d.supplier, ''),
					char(10)
				), '')
				FROM repo_dependencies rd
				JOIN dependencies d ON d.dependency_id = rd.dependency_id
				WHERE rd.run_uuid = ? AND rd.repo_id = r.repo_id
			) AS dependency_details,
			(SELECT COUNT(1) FROM dependabot_alerts da WHERE da.run_uuid = ? AND da.repo_id = r.repo_id AND lower(da.state) = 'open') AS open_dependabot_alerts,
			(SELECT COUNT(1) FROM dependabot_alerts da WHERE da.run_uuid = ? AND da.repo_id = r.repo_id AND lower(da.state) = 'open' AND lower(da.severity) = 'critical') AS open_critical_dependabot_alerts,
			(SELECT COUNT(1) FROM dependabot_alerts da WHERE da.run_uuid = ? AND da.repo_id = r.repo_id) AS total_dependabot_alerts,
			(
				SELECT COALESCE(group_concat(
					'alert_number=' || da.alert_number ||
					';state=' || COALESCE(da.state, '') ||
					';severity=' || COALESCE(da.severity, '') ||
					';ecosystem=' || COALESCE(da.ecosystem, '') ||
					';package_name=' || COALESCE(da.package_name, '') ||
					';manifest_path=' || COALESCE(da.manifest_path, '') ||
					';created_at=' || COALESCE(da.created_at, '') ||
					';updated_at=' || COALESCE(da.updated_at, '') ||
					';fixed_at=' || COALESCE(da.fixed_at, '') ||
					';dismissed_reason=' || COALESCE(da.dismissed_reason, '') ||
					';dependency_id=' || COALESCE(CAST(da.dependency_id AS TEXT), ''),
					char(10)
				), '')
				FROM dependabot_alerts da
				WHERE da.run_uuid = ? AND da.repo_id = r.repo_id
			) AS dependabot_alert_details,
			(SELECT COUNT(1) FROM code_scanning_alerts ca WHERE ca.run_uuid = ? AND ca.repo_id = r.repo_id AND lower(ca.state) = 'open') AS open_code_scanning_alerts,
			(SELECT COUNT(1) FROM code_scanning_alerts ca WHERE ca.run_uuid = ? AND ca.repo_id = r.repo_id) AS total_code_scanning_alerts,
			(
				SELECT COALESCE(group_concat(
					'alert_number=' || ca.alert_number ||
					';state=' || COALESCE(ca.state, '') ||
					';rule_id=' || COALESCE(ca.rule_id, '') ||
					';tool=' || COALESCE(ca.tool, '') ||
						';severity=' || COALESCE(ca.severity, '') ||
						';security_severity=' || COALESCE(ca.security_severity, '') ||
						';created_at=' || COALESCE(ca.created_at, '') ||
						';fixed_at=' || COALESCE(ca.fixed_at, '') ||
						';most_recent_ref=' || COALESCE(ca.most_recent_ref, '') ||
						';most_recent_commit_sha=' || COALESCE(ca.most_recent_commit_sha, '') ||
						';most_recent_path=' || COALESCE(ca.most_recent_path, '') ||
						';most_recent_state=' || COALESCE(ca.most_recent_state, ''),
						char(10)
					), '')
					FROM code_scanning_alerts ca
				WHERE ca.run_uuid = ? AND ca.repo_id = r.repo_id
			) AS code_scanning_alert_details,
			(SELECT COUNT(1) FROM secret_scanning_alerts sa WHERE sa.run_uuid = ? AND sa.repo_id = r.repo_id AND lower(sa.state) = 'open') AS open_secret_scanning_alerts,
			(SELECT COUNT(1) FROM secret_scanning_alerts sa WHERE sa.run_uuid = ? AND sa.repo_id = r.repo_id) AS total_secret_scanning_alerts,
			(
				SELECT COALESCE(group_concat(
					'alert_number=' || sa.alert_number ||
					';state=' || COALESCE(sa.state, '') ||
					';secret_type=' || COALESCE(sa.secret_type, '') ||
					';resolution=' || COALESCE(sa.resolution, '') ||
					';created_at=' || COALESCE(sa.created_at, '') ||
					';updated_at=' || COALESCE(sa.updated_at, '') ||
					';resolved_at=' || COALESCE(sa.resolved_at, ''),
					char(10)
				), '')
				FROM secret_scanning_alerts sa
				WHERE sa.run_uuid = ? AND sa.repo_id = r.repo_id
			) AS secret_scanning_alert_details,
			(SELECT COUNT(1) FROM repo_rulesets rr WHERE rr.run_uuid = ? AND rr.repo_id = r.repo_id) AS total_rulesets,
				(
						SELECT COALESCE(group_concat(
							'ruleset_id=' || rr.ruleset_id ||
							';name=' || COALESCE(rr.name, '') ||
							';enforcement=' || COALESCE(rr.enforcement, '') ||
							';target=' || COALESCE(rr.target, '') ||
							';source=' || COALESCE(rr.source, '') ||
							';source_type=' || COALESCE(rr.source_type, '') ||
							';created_at=' || COALESCE(rr.created_at, '') ||
							';updated_at=' || COALESCE(rr.updated_at, ''),
							char(10)
						), '')
						FROM repo_rulesets rr
					WHERE rr.run_uuid = ? AND rr.repo_id = r.repo_id
				) AS ruleset_details
			FROM repos r
			WHERE r.run_uuid = ?
		ORDER BY open_critical_dependabot_alerts DESC, open_dependabot_alerts DESC, r.full_name ASC
	`

	rows, err := db.Query(
		query,
		runUUID, // sbom_spdx_id
		runUUID, // sbom_spdx_version
		runUUID, // sbom_document_name
		runUUID, // sbom_data_license
		runUUID, // sbom_document_namespace
		runUUID, // sbom_generated_at
		runUUID, // sbom_creation_creators
		runUUID, // sbom_document_describes_count
		runUUID, // sbom_package_count
		runUUID, // sbom_relationship_count
		runUUID, // dependency_count
		runUUID, // dependency_details
		runUUID, // open_dependabot_alerts
		runUUID, // open_critical_dependabot_alerts
		runUUID, // total_dependabot_alerts
		runUUID, // dependabot_alert_details
		runUUID, // open_code_scanning_alerts
		runUUID, // total_code_scanning_alerts
		runUUID, // code_scanning_alert_details
		runUUID, // open_secret_scanning_alerts
		runUUID, // total_secret_scanning_alerts
		runUUID, // secret_scanning_alert_details
		runUUID, // total_rulesets
		runUUID, // ruleset_details
		runUUID, // repos filter
	)
	if err != nil {
		return err
	}
	defer rows.Close()

	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	headers, err := rows.Columns()
	if err != nil {
		return err
	}
	if err := w.Write(headers); err != nil {
		return err
	}

	for rows.Next() {
		vals := make([]interface{}, len(headers))
		valPtrs := make([]interface{}, len(headers))
		for i := range vals {
			valPtrs[i] = &vals[i]
		}
		if err := rows.Scan(valPtrs...); err != nil {
			return err
		}
		record := make([]string, len(headers))
		for i, v := range vals {
			record[i] = stringifyDBValue(v)
		}
		if err := w.Write(record); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return nil
}

func stringPtr(v string) *string {
	return &v
}

func resolveAlertRepoID(repoIDByName map[string]int64, repo *github.Repository) (int64, bool) {
	if repo != nil {
		if repoID := repo.GetID(); repoID != 0 {
			return repoID, true
		}
		if fullName := repo.GetFullName(); fullName != "" {
			if id, ok := repoIDByName[fullName]; ok {
				return id, true
			}
		}
		if name := repo.GetName(); name != "" {
			if id, ok := repoIDByName[name]; ok {
				return id, true
			}
		}
	}
	return 0, false
}

func dependabotAlertKey(a *github.DependabotAlert) string {
	if a == nil {
		return ""
	}
	repo := a.GetRepository()
	if repo != nil && repo.GetID() != 0 {
		return fmt.Sprintf("%d:%d", repo.GetID(), a.GetNumber())
	}
	return firstNonEmpty(a.GetHTMLURL(), a.GetURL(), fmt.Sprintf("unknown:%d", a.GetNumber()))
}

func codeScanningAlertKey(a *github.Alert) string {
	if a == nil {
		return ""
	}
	repo := a.GetRepository()
	if repo != nil && repo.GetID() != 0 {
		return fmt.Sprintf("%d:%d", repo.GetID(), a.GetNumber())
	}
	if a.GetHTMLURL() != "" {
		return a.GetHTMLURL()
	}
	return fmt.Sprintf("unknown:%d", a.GetNumber())
}

func secretScanningAlertKey(a *github.SecretScanningAlert) string {
	if a == nil {
		return ""
	}
	repo := a.GetRepository()
	if repo != nil && repo.GetID() != 0 {
		return fmt.Sprintf("%d:%d", repo.GetID(), a.GetNumber())
	}
	if a.GetHTMLURL() != "" {
		return a.GetHTMLURL()
	}
	return fmt.Sprintf("unknown:%d", a.GetNumber())
}

func extractPURLFromDependency(pkg *github.RepoDependencies) string {
	if pkg == nil {
		return ""
	}
	for _, ref := range pkg.ExternalRefs {
		if ref == nil {
			continue
		}
		if strings.EqualFold(ref.ReferenceType, "purl") || strings.EqualFold(ref.ReferenceType, "package-manager") {
			return ref.ReferenceLocator
		}
	}
	return ""
}

func ecosystemFromPURL(purl string) string {
	if !strings.HasPrefix(purl, "pkg:") {
		return ""
	}
	rest := strings.TrimPrefix(purl, "pkg:")
	if rest == "" {
		return ""
	}
	end := strings.Index(rest, "/")
	if end == -1 {
		end = strings.Index(rest, "@")
	}
	if end == -1 {
		return rest
	}
	return rest[:end]
}

func sbomCreatedAt(doc *github.SBOMInfo) string {
	if doc == nil || doc.CreationInfo == nil {
		return ""
	}
	return formatGitHubTimePtr(doc.CreationInfo.Created)
}

func sbomCreators(doc *github.SBOMInfo) string {
	if doc == nil || doc.CreationInfo == nil {
		return ""
	}
	return strings.Join(doc.CreationInfo.Creators, ",")
}

func nullableInt(v int) interface{} {
	if v == 0 {
		return nil
	}
	return v
}

func snapshotCodeScanningInstance(inst *github.MostRecentInstance) codeScanningInstanceSnapshot {
	s := codeScanningInstanceSnapshot{}
	if inst == nil {
		return s
	}
	s.ref = inst.GetRef()
	s.commitSHA = inst.GetCommitSHA()
	s.state = inst.GetState()
	s.category = inst.GetCategory()
	s.classifications = strings.Join(inst.Classifications, ",")
	if inst.Location != nil {
		s.path = inst.Location.GetPath()
		s.startLine = nullableInt(inst.Location.GetStartLine())
		s.endLine = nullableInt(inst.Location.GetEndLine())
		s.startColumn = nullableInt(inst.Location.GetStartColumn())
		s.endColumn = nullableInt(inst.Location.GetEndColumn())
	}
	return s
}

func lookupDependencyIDTx(tx *sql.Tx, ecosystem, name string) (interface{}, error) {
	if safeStr(name) == "" {
		return nil, nil
	}
	var depID int64
	err := tx.QueryRow(`
		SELECT dependency_id FROM dependencies
		WHERE ecosystem = ? AND name = ?
		ORDER BY CASE WHEN version = '' THEN 1 ELSE 0 END, dependency_id DESC
		LIMIT 1
	`, safeStr(ecosystem), safeStr(name)).Scan(&depID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return depID, nil
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func formatTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return formatTime(*t)
}

func formatGitHubTimePtr(t *github.Timestamp) string {
	if t == nil {
		return ""
	}
	return formatTime(t.Time)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func safeStr(s string) string {
	return strings.TrimSpace(s)
}

func nullableInt64(ok bool, v int64) interface{} {
	if !ok {
		return nil
	}
	return v
}

func stringifyDBValue(v interface{}) string {
	switch x := v.(type) {
	case nil:
		return ""
	case []byte:
		return string(x)
	case string:
		return x
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		if x {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", x)
	}
}
