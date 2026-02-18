package main

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
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
		`CREATE TABLE IF NOT EXISTS repo_owners (
			run_uuid TEXT NOT NULL,
			repo_id INTEGER NOT NULL,
			owner_id INTEGER,
			login TEXT,
			node_id TEXT,
			type TEXT,
			site_admin INTEGER,
			html_url TEXT,
			PRIMARY KEY (run_uuid, repo_id)
		);`,
		`CREATE TABLE IF NOT EXISTS repo_permissions (
			run_uuid TEXT NOT NULL,
			repo_id INTEGER NOT NULL,
			admin INTEGER,
			maintain INTEGER,
			push INTEGER,
			triage INTEGER,
			pull INTEGER,
			PRIMARY KEY (run_uuid, repo_id)
		);`,
		`CREATE TABLE IF NOT EXISTS repo_urls (
			run_uuid TEXT NOT NULL,
			repo_id INTEGER NOT NULL,
			url TEXT,
			archive_url TEXT,
			assignees_url TEXT,
			blobs_url TEXT,
			branches_url TEXT,
			collaborators_url TEXT,
			comments_url TEXT,
			commits_url TEXT,
			compare_url TEXT,
			contents_url TEXT,
			contributors_url TEXT,
			deployments_url TEXT,
			downloads_url TEXT,
			events_url TEXT,
			forks_url TEXT,
			git_commits_url TEXT,
			git_refs_url TEXT,
			git_tags_url TEXT,
			hooks_url TEXT,
			issue_comment_url TEXT,
			issue_events_url TEXT,
			issues_url TEXT,
			keys_url TEXT,
			labels_url TEXT,
			languages_url TEXT,
			merges_url TEXT,
			milestones_url TEXT,
			notifications_url TEXT,
			pulls_url TEXT,
			releases_url TEXT,
			stargazers_url TEXT,
			statuses_url TEXT,
			subscribers_url TEXT,
			subscription_url TEXT,
			tags_url TEXT,
			trees_url TEXT,
			teams_url TEXT,
			PRIMARY KEY (run_uuid, repo_id)
		);`,
		`CREATE TABLE IF NOT EXISTS repo_merge_policies (
			run_uuid TEXT NOT NULL,
			repo_id INTEGER NOT NULL,
			allow_rebase_merge INTEGER,
			allow_update_branch INTEGER,
			allow_squash_merge INTEGER,
			allow_merge_commit INTEGER,
			allow_auto_merge INTEGER,
			allow_forking INTEGER,
			delete_branch_on_merge INTEGER,
			use_squash_pr_title_as_default INTEGER,
			web_commit_signoff_required INTEGER,
			PRIMARY KEY (run_uuid, repo_id)
		);`,
		`CREATE TABLE IF NOT EXISTS sbom_document_describes (
			run_uuid TEXT NOT NULL,
			sbom_id INTEGER NOT NULL,
			spdx_element_id TEXT NOT NULL,
			PRIMARY KEY (run_uuid, sbom_id, spdx_element_id)
		);`,
		`CREATE TABLE IF NOT EXISTS sbom_package_external_refs (
			run_uuid TEXT NOT NULL,
			sbom_id INTEGER NOT NULL,
			dependency_id INTEGER,
			spdx_package_id TEXT,
			reference_category TEXT,
			reference_type TEXT,
			reference_locator TEXT,
			PRIMARY KEY (run_uuid, sbom_id, spdx_package_id, reference_category, reference_type, reference_locator)
		);`,
		`CREATE TABLE IF NOT EXISTS dependabot_security_advisories (
			run_uuid TEXT NOT NULL,
			repo_id INTEGER NOT NULL,
			alert_number INTEGER NOT NULL,
			ghsa_id TEXT,
			cve_id TEXT,
			summary TEXT,
			description TEXT,
			severity TEXT,
			cvss_score REAL,
			cvss_vector_string TEXT,
			epss_percentage REAL,
			epss_percentile REAL,
			published_at TEXT,
			updated_at TEXT,
			withdrawn_at TEXT,
			PRIMARY KEY (run_uuid, repo_id, alert_number)
		);`,
		`CREATE TABLE IF NOT EXISTS dependabot_advisory_vulnerabilities (
			run_uuid TEXT NOT NULL,
			repo_id INTEGER NOT NULL,
			alert_number INTEGER NOT NULL,
			row_num INTEGER NOT NULL,
			ecosystem TEXT,
			package_name TEXT,
			severity TEXT,
			vulnerable_version_range TEXT,
			first_patched_version TEXT,
			patched_versions TEXT,
			vulnerable_functions TEXT,
			PRIMARY KEY (run_uuid, repo_id, alert_number, row_num)
		);`,
		`CREATE TABLE IF NOT EXISTS dependabot_advisory_identifiers (
			run_uuid TEXT NOT NULL,
			repo_id INTEGER NOT NULL,
			alert_number INTEGER NOT NULL,
			row_num INTEGER NOT NULL,
			value TEXT,
			type TEXT,
			PRIMARY KEY (run_uuid, repo_id, alert_number, row_num)
		);`,
		`CREATE TABLE IF NOT EXISTS dependabot_advisory_references (
			run_uuid TEXT NOT NULL,
			repo_id INTEGER NOT NULL,
			alert_number INTEGER NOT NULL,
			row_num INTEGER NOT NULL,
			url TEXT,
			PRIMARY KEY (run_uuid, repo_id, alert_number, row_num)
		);`,
		`CREATE TABLE IF NOT EXISTS dependabot_advisory_cwes (
			run_uuid TEXT NOT NULL,
			repo_id INTEGER NOT NULL,
			alert_number INTEGER NOT NULL,
			row_num INTEGER NOT NULL,
			cwe_id TEXT,
			name TEXT,
			PRIMARY KEY (run_uuid, repo_id, alert_number, row_num)
		);`,
		`CREATE TABLE IF NOT EXISTS code_scanning_alert_instances (
			run_uuid TEXT NOT NULL,
			repo_id INTEGER NOT NULL,
			alert_number INTEGER NOT NULL,
			row_num INTEGER NOT NULL,
			ref TEXT,
			analysis_key TEXT,
			category TEXT,
			environment TEXT,
			state TEXT,
			commit_sha TEXT,
			message_text TEXT,
			path TEXT,
			start_line INTEGER,
			end_line INTEGER,
			start_column INTEGER,
			end_column INTEGER,
			PRIMARY KEY (run_uuid, repo_id, alert_number, row_num)
		);`,
		`CREATE TABLE IF NOT EXISTS code_scanning_rule_tags (
			run_uuid TEXT NOT NULL,
			repo_id INTEGER NOT NULL,
			alert_number INTEGER NOT NULL,
			row_num INTEGER NOT NULL,
			tag TEXT,
			PRIMARY KEY (run_uuid, repo_id, alert_number, row_num)
		);`,
		`CREATE TABLE IF NOT EXISTS secret_scanning_first_locations (
			run_uuid TEXT NOT NULL,
			repo_id INTEGER NOT NULL,
			alert_number INTEGER NOT NULL,
			path TEXT,
			start_line INTEGER,
			end_line INTEGER,
			start_column INTEGER,
			end_column INTEGER,
			blob_sha TEXT,
			blob_url TEXT,
			commit_sha TEXT,
			commit_url TEXT,
			pull_request_comment_url TEXT,
			PRIMARY KEY (run_uuid, repo_id, alert_number)
		);`,
		`CREATE TABLE IF NOT EXISTS repo_ruleset_bypass_actors (
			run_uuid TEXT NOT NULL,
			repo_id INTEGER NOT NULL,
			ruleset_id INTEGER NOT NULL,
			row_num INTEGER NOT NULL,
			actor_id INTEGER,
			actor_type TEXT,
			bypass_mode TEXT,
			PRIMARY KEY (run_uuid, repo_id, ruleset_id, row_num)
		);`,
		`CREATE TABLE IF NOT EXISTS repo_ruleset_links (
			run_uuid TEXT NOT NULL,
			repo_id INTEGER NOT NULL,
			ruleset_id INTEGER NOT NULL,
			self_href TEXT,
			html_href TEXT,
			PRIMARY KEY (run_uuid, repo_id, ruleset_id)
		);`,
		`CREATE TABLE IF NOT EXISTS repo_ruleset_rule_entries (
			run_uuid TEXT NOT NULL,
			repo_id INTEGER NOT NULL,
			ruleset_id INTEGER NOT NULL,
			row_num INTEGER NOT NULL,
			rule_type TEXT,
			parameters_json TEXT,
			PRIMARY KEY (run_uuid, repo_id, ruleset_id, row_num)
		);`,
		`CREATE TABLE IF NOT EXISTS repo_ruleset_condition_repo_ids (
			run_uuid TEXT NOT NULL,
			repo_id INTEGER NOT NULL,
			ruleset_id INTEGER NOT NULL,
			repository_id INTEGER NOT NULL,
			PRIMARY KEY (run_uuid, repo_id, ruleset_id, repository_id)
		);`,
		`CREATE TABLE IF NOT EXISTS repo_ruleset_condition_repo_names (
			run_uuid TEXT NOT NULL,
			repo_id INTEGER NOT NULL,
			ruleset_id INTEGER NOT NULL,
			include_exclude TEXT NOT NULL,
			repo_name TEXT NOT NULL,
			PRIMARY KEY (run_uuid, repo_id, ruleset_id, include_exclude, repo_name)
		);`,
		`CREATE TABLE IF NOT EXISTS repo_ruleset_condition_org_ids (
			run_uuid TEXT NOT NULL,
			repo_id INTEGER NOT NULL,
			ruleset_id INTEGER NOT NULL,
			organization_id INTEGER NOT NULL,
			PRIMARY KEY (run_uuid, repo_id, ruleset_id, organization_id)
		);`,
		`CREATE TABLE IF NOT EXISTS repo_ruleset_condition_org_names (
			run_uuid TEXT NOT NULL,
			repo_id INTEGER NOT NULL,
			ruleset_id INTEGER NOT NULL,
			include_exclude TEXT NOT NULL,
			organization_name TEXT NOT NULL,
			PRIMARY KEY (run_uuid, repo_id, ruleset_id, include_exclude, organization_name)
		);`,
		`CREATE TABLE IF NOT EXISTS repo_ruleset_condition_property_targets (
			run_uuid TEXT NOT NULL,
			repo_id INTEGER NOT NULL,
			ruleset_id INTEGER NOT NULL,
			target_scope TEXT NOT NULL,
			include_exclude TEXT NOT NULL,
			name TEXT NOT NULL,
			property_values TEXT,
			source TEXT,
			PRIMARY KEY (run_uuid, repo_id, ruleset_id, target_scope, include_exclude, name, property_values)
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
			{name: "node_id", definition: "TEXT"},
			{name: "owner_login", definition: "TEXT"},
			{name: "owner_id", definition: "INTEGER"},
			{name: "owner_type", definition: "TEXT"},
			{name: "owner_site_admin", definition: "INTEGER"},
			{name: "html_url", definition: "TEXT"},
			{name: "clone_url", definition: "TEXT"},
			{name: "git_url", definition: "TEXT"},
			{name: "mirror_url", definition: "TEXT"},
			{name: "ssh_url", definition: "TEXT"},
			{name: "svn_url", definition: "TEXT"},
			{name: "network_count", definition: "INTEGER"},
			{name: "subscribers_count", definition: "INTEGER"},
			{name: "watchers_count", definition: "INTEGER"},
			{name: "watchers", definition: "INTEGER"},
			{name: "auto_init", definition: "INTEGER"},
			{name: "allow_rebase_merge", definition: "INTEGER"},
			{name: "allow_update_branch", definition: "INTEGER"},
			{name: "allow_squash_merge", definition: "INTEGER"},
			{name: "allow_merge_commit", definition: "INTEGER"},
			{name: "allow_auto_merge", definition: "INTEGER"},
			{name: "allow_forking", definition: "INTEGER"},
			{name: "web_commit_signoff_required", definition: "INTEGER"},
			{name: "delete_branch_on_merge", definition: "INTEGER"},
			{name: "use_squash_pr_title_as_default", definition: "INTEGER"},
			{name: "squash_merge_commit_title", definition: "TEXT"},
			{name: "squash_merge_commit_message", definition: "TEXT"},
			{name: "merge_commit_title", definition: "TEXT"},
			{name: "merge_commit_message", definition: "TEXT"},
			{name: "has_downloads", definition: "INTEGER"},
			{name: "license_key", definition: "TEXT"},
			{name: "license_name", definition: "TEXT"},
			{name: "license_url", definition: "TEXT"},
			{name: "license_node_id", definition: "TEXT"},
			{name: "secret_scanning_validity_checks_status", definition: "TEXT"},
			{name: "master_branch", definition: "TEXT"},
			{name: "role_name", definition: "TEXT"},
			{name: "parent_repo_id", definition: "INTEGER"},
			{name: "source_repo_id", definition: "INTEGER"},
			{name: "template_repo_id", definition: "INTEGER"},
			{name: "organization_id", definition: "INTEGER"},
			{name: "team_id", definition: "INTEGER"},
			{name: "private_forks", definition: "INTEGER"},
			{name: "custom_properties_json", definition: "TEXT"},
		},
		"dependencies": {
			{name: "license_declared", definition: "TEXT"},
			{name: "download_location", definition: "TEXT"},
			{name: "files_analyzed", definition: "INTEGER"},
		},
		"repo_dependencies": {
			{name: "scope", definition: "TEXT"},
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
		"sbom_relationships": {
			{name: "from_spdx_id", definition: "TEXT"},
			{name: "to_spdx_id", definition: "TEXT"},
		},
		"dependabot_alerts": {
			{name: "url", definition: "TEXT"},
			{name: "html_url", definition: "TEXT"},
			{name: "dismissed_at", definition: "TEXT"},
			{name: "dismissed_comment", definition: "TEXT"},
			{name: "auto_dismissed_at", definition: "TEXT"},
			{name: "dependency_scope", definition: "TEXT"},
			{name: "advisory_ghsa_id", definition: "TEXT"},
			{name: "advisory_cve_id", definition: "TEXT"},
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
			{name: "updated_at", definition: "TEXT"},
			{name: "closed_at", definition: "TEXT"},
			{name: "url", definition: "TEXT"},
			{name: "html_url", definition: "TEXT"},
			{name: "instances_url", definition: "TEXT"},
			{name: "dismissed_at", definition: "TEXT"},
			{name: "dismissed_reason", definition: "TEXT"},
			{name: "dismissed_comment", definition: "TEXT"},
			{name: "rule_description", definition: "TEXT"},
			{name: "tool_guid", definition: "TEXT"},
			{name: "tool_version", definition: "TEXT"},
			{name: "most_recent_analysis_key", definition: "TEXT"},
			{name: "most_recent_environment", definition: "TEXT"},
		},
		"secret_scanning_alerts": {
			{name: "url", definition: "TEXT"},
			{name: "html_url", definition: "TEXT"},
			{name: "locations_url", definition: "TEXT"},
			{name: "secret_type_display_name", definition: "TEXT"},
			{name: "secret", definition: "TEXT"},
			{name: "is_base64_encoded", definition: "INTEGER"},
			{name: "multi_repo", definition: "INTEGER"},
			{name: "publicly_leaked", definition: "INTEGER"},
			{name: "push_protection_bypassed", definition: "INTEGER"},
			{name: "push_protection_bypassed_by_login", definition: "TEXT"},
			{name: "push_protection_bypassed_by_id", definition: "INTEGER"},
			{name: "push_protection_bypassed_at", definition: "TEXT"},
			{name: "resolution_comment", definition: "TEXT"},
			{name: "push_protection_bypass_request_comment", definition: "TEXT"},
			{name: "push_protection_bypass_request_html_url", definition: "TEXT"},
			{name: "push_protection_bypass_request_reviewer_login", definition: "TEXT"},
			{name: "push_protection_bypass_request_reviewer_id", definition: "INTEGER"},
			{name: "validity", definition: "TEXT"},
			{name: "has_more_locations", definition: "INTEGER"},
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
			{name: "rules_count", definition: "INTEGER"},
			{name: "conditions_json", definition: "TEXT"},
			{name: "rules_json", definition: "TEXT"},
			{name: "links_self_href", definition: "TEXT"},
			{name: "links_html_href", definition: "TEXT"},
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
	licenseKey := ""
	licenseName := ""
	licenseURL := ""
	licenseNodeID := ""
	if repo.License != nil {
		licenseSPDX = repo.License.GetSPDXID()
		licenseKey = repo.License.GetKey()
		licenseName = repo.License.GetName()
		licenseURL = repo.License.GetURL()
		licenseNodeID = ""
	}
	advancedSecurityStatus := ""
	secretScanningStatus := ""
	secretScanningPushProtectionStatus := ""
	dependabotSecurityUpdatesStatus := ""
	secretScanningValidityChecksStatus := ""
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
		if repo.SecurityAndAnalysis.SecretScanningValidityChecks != nil {
			secretScanningValidityChecksStatus = repo.SecurityAndAnalysis.SecretScanningValidityChecks.GetStatus()
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
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
	if err != nil {
		return err
	}

	customPropertiesJSON := jsonString(repo.CustomProperties)

	_, err = db.Exec(`
		UPDATE repos
		SET
			node_id = ?, owner_login = ?, owner_id = ?, owner_type = ?, owner_site_admin = ?,
			html_url = ?, clone_url = ?, git_url = ?, mirror_url = ?, ssh_url = ?, svn_url = ?,
			network_count = ?, subscribers_count = ?, watchers_count = ?, watchers = ?, auto_init = ?,
			allow_rebase_merge = ?, allow_update_branch = ?, allow_squash_merge = ?, allow_merge_commit = ?,
			allow_auto_merge = ?, allow_forking = ?, web_commit_signoff_required = ?, delete_branch_on_merge = ?,
			use_squash_pr_title_as_default = ?, squash_merge_commit_title = ?, squash_merge_commit_message = ?,
			merge_commit_title = ?, merge_commit_message = ?, has_downloads = ?,
			license_key = ?, license_name = ?, license_url = ?, license_node_id = ?,
			secret_scanning_validity_checks_status = ?, master_branch = ?, role_name = ?,
			parent_repo_id = ?, source_repo_id = ?, template_repo_id = ?, organization_id = ?, team_id = ?,
			private_forks = ?, custom_properties_json = ?
		WHERE run_uuid = ? AND repo_id = ?
	`,
		repo.GetNodeID(), repo.GetOwner().GetLogin(), nullableInt64Value(repo.GetOwner().GetID()), repo.GetOwner().GetType(), boolToInt(repo.GetOwner().GetSiteAdmin()),
		repo.GetHTMLURL(), repo.GetCloneURL(), repo.GetGitURL(), repo.GetMirrorURL(), repo.GetSSHURL(), repo.GetSVNURL(),
		repo.GetNetworkCount(), repo.GetSubscribersCount(), repo.GetWatchersCount(), repo.GetWatchers(), boolToInt(repo.GetAutoInit()),
		boolToInt(repo.GetAllowRebaseMerge()), boolToInt(repo.GetAllowUpdateBranch()), boolToInt(repo.GetAllowSquashMerge()), boolToInt(repo.GetAllowMergeCommit()),
		boolToInt(repo.GetAllowAutoMerge()), boolToInt(repo.GetAllowForking()), boolToInt(repo.GetWebCommitSignoffRequired()), boolToInt(repo.GetDeleteBranchOnMerge()),
		boolToInt(repo.GetUseSquashPRTitleAsDefault()), repo.GetSquashMergeCommitTitle(), repo.GetSquashMergeCommitMessage(),
		repo.GetMergeCommitTitle(), repo.GetMergeCommitMessage(), boolToInt(repo.GetHasDownloads()),
		licenseKey, licenseName, licenseURL, licenseNodeID,
		secretScanningValidityChecksStatus, repo.GetMasterBranch(), repo.GetRoleName(),
		nullableInt64Value(repo.GetParent().GetID()), nullableInt64Value(repo.GetSource().GetID()), nullableInt64Value(repo.GetTemplateRepository().GetID()), nullableInt64Value(repo.GetOrganization().GetID()), nullableInt64Value(repo.GetTeamID()),
		nil, customPropertiesJSON,
		runUUID, repo.GetID(),
	)
	if err != nil {
		return err
	}

	if _, err = db.Exec(`
		INSERT INTO repo_owners(run_uuid, repo_id, owner_id, login, node_id, type, site_admin, html_url)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(run_uuid, repo_id) DO UPDATE SET
			owner_id = excluded.owner_id,
			login = excluded.login,
			node_id = excluded.node_id,
			type = excluded.type,
			site_admin = excluded.site_admin,
			html_url = excluded.html_url
	`,
		runUUID, repo.GetID(), nullableInt64Value(repo.GetOwner().GetID()), repo.GetOwner().GetLogin(), repo.GetOwner().GetNodeID(), repo.GetOwner().GetType(), boolToInt(repo.GetOwner().GetSiteAdmin()), repo.GetOwner().GetHTMLURL(),
	); err != nil {
		return err
	}

	if _, err = db.Exec(`
		INSERT INTO repo_permissions(run_uuid, repo_id, admin, maintain, push, triage, pull)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(run_uuid, repo_id) DO UPDATE SET
			admin = excluded.admin,
			maintain = excluded.maintain,
			push = excluded.push,
			triage = excluded.triage,
			pull = excluded.pull
	`,
		runUUID, repo.GetID(), boolToInt(repo.GetPermissions().GetAdmin()), boolToInt(repo.GetPermissions().GetMaintain()), boolToInt(repo.GetPermissions().GetPush()), boolToInt(repo.GetPermissions().GetTriage()), boolToInt(repo.GetPermissions().GetPull()),
	); err != nil {
		return err
	}

	if _, err = db.Exec(`
		INSERT INTO repo_urls(
			run_uuid, repo_id, url, archive_url, assignees_url, blobs_url, branches_url, collaborators_url,
			comments_url, commits_url, compare_url, contents_url, contributors_url, deployments_url,
			downloads_url, events_url, forks_url, git_commits_url, git_refs_url, git_tags_url, hooks_url,
			issue_comment_url, issue_events_url, issues_url, keys_url, labels_url, languages_url, merges_url,
			milestones_url, notifications_url, pulls_url, releases_url, stargazers_url, statuses_url,
			subscribers_url, subscription_url, tags_url, trees_url, teams_url
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(run_uuid, repo_id) DO UPDATE SET
			url = excluded.url,
			archive_url = excluded.archive_url,
			assignees_url = excluded.assignees_url,
			blobs_url = excluded.blobs_url,
			branches_url = excluded.branches_url,
			collaborators_url = excluded.collaborators_url,
			comments_url = excluded.comments_url,
			commits_url = excluded.commits_url,
			compare_url = excluded.compare_url,
			contents_url = excluded.contents_url,
			contributors_url = excluded.contributors_url,
			deployments_url = excluded.deployments_url,
			downloads_url = excluded.downloads_url,
			events_url = excluded.events_url,
			forks_url = excluded.forks_url,
			git_commits_url = excluded.git_commits_url,
			git_refs_url = excluded.git_refs_url,
			git_tags_url = excluded.git_tags_url,
			hooks_url = excluded.hooks_url,
			issue_comment_url = excluded.issue_comment_url,
			issue_events_url = excluded.issue_events_url,
			issues_url = excluded.issues_url,
			keys_url = excluded.keys_url,
			labels_url = excluded.labels_url,
			languages_url = excluded.languages_url,
			merges_url = excluded.merges_url,
			milestones_url = excluded.milestones_url,
			notifications_url = excluded.notifications_url,
			pulls_url = excluded.pulls_url,
			releases_url = excluded.releases_url,
			stargazers_url = excluded.stargazers_url,
			statuses_url = excluded.statuses_url,
			subscribers_url = excluded.subscribers_url,
			subscription_url = excluded.subscription_url,
			tags_url = excluded.tags_url,
			trees_url = excluded.trees_url,
			teams_url = excluded.teams_url
	`,
		runUUID, repo.GetID(), repo.GetURL(), repo.GetArchiveURL(), repo.GetAssigneesURL(), repo.GetBlobsURL(), repo.GetBranchesURL(), repo.GetCollaboratorsURL(),
		repo.GetCommentsURL(), repo.GetCommitsURL(), repo.GetCompareURL(), repo.GetContentsURL(), repo.GetContributorsURL(), repo.GetDeploymentsURL(),
		repo.GetDownloadsURL(), repo.GetEventsURL(), repo.GetForksURL(), repo.GetGitCommitsURL(), repo.GetGitRefsURL(), repo.GetGitTagsURL(), repo.GetHooksURL(),
		repo.GetIssueCommentURL(), repo.GetIssueEventsURL(), repo.GetIssuesURL(), repo.GetKeysURL(), repo.GetLabelsURL(), repo.GetLanguagesURL(), repo.GetMergesURL(),
		repo.GetMilestonesURL(), repo.GetNotificationsURL(), repo.GetPullsURL(), repo.GetReleasesURL(), repo.GetStargazersURL(), repo.GetStatusesURL(),
		repo.GetSubscribersURL(), repo.GetSubscriptionURL(), repo.GetTagsURL(), repo.GetTreesURL(), repo.GetTeamsURL(),
	); err != nil {
		return err
	}

	_, err = db.Exec(`
		INSERT INTO repo_merge_policies(
			run_uuid, repo_id, allow_rebase_merge, allow_update_branch, allow_squash_merge, allow_merge_commit,
			allow_auto_merge, allow_forking, delete_branch_on_merge, use_squash_pr_title_as_default, web_commit_signoff_required
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(run_uuid, repo_id) DO UPDATE SET
			allow_rebase_merge = excluded.allow_rebase_merge,
			allow_update_branch = excluded.allow_update_branch,
			allow_squash_merge = excluded.allow_squash_merge,
			allow_merge_commit = excluded.allow_merge_commit,
			allow_auto_merge = excluded.allow_auto_merge,
			allow_forking = excluded.allow_forking,
			delete_branch_on_merge = excluded.delete_branch_on_merge,
			use_squash_pr_title_as_default = excluded.use_squash_pr_title_as_default,
			web_commit_signoff_required = excluded.web_commit_signoff_required
	`,
		runUUID, repo.GetID(), boolToInt(repo.GetAllowRebaseMerge()), boolToInt(repo.GetAllowUpdateBranch()), boolToInt(repo.GetAllowSquashMerge()),
		boolToInt(repo.GetAllowMergeCommit()), boolToInt(repo.GetAllowAutoMerge()), boolToInt(repo.GetAllowForking()),
		boolToInt(repo.GetDeleteBranchOnMerge()), boolToInt(repo.GetUseSquashPRTitleAsDefault()), boolToInt(repo.GetWebCommitSignoffRequired()),
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
		depID, err := upsertDependencyTx(
			tx,
			ecosystem,
			pkg.GetName(),
			pkg.GetVersionInfo(),
			purl,
			pkg.GetLicenseConcluded(),
			"",
			pkg.GetLicenseDeclared(),
			pkg.GetDownloadLocation(),
			boolPtrToIntPtr(pkg.FilesAnalyzed),
		)
		if err != nil {
			return err
		}
		pkgIDMap[pkg.GetSPDXID()] = depID
		if _, err := tx.Exec(`
			INSERT INTO repo_dependencies(run_uuid, repo_id, dependency_id, source, snapshot_at, scope)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(run_uuid, repo_id, dependency_id, source) DO UPDATE SET
				snapshot_at = excluded.snapshot_at,
				scope = excluded.scope
		`, runUUID, repoID, depID, "sbom", time.Now().UTC().Format(time.RFC3339), pkg.GetSPDXID()); err != nil {
			return err
		}

		for _, ref := range pkg.ExternalRefs {
			if ref == nil {
				continue
			}
			_, err := tx.Exec(`
				INSERT OR IGNORE INTO sbom_package_external_refs(
					run_uuid, sbom_id, dependency_id, spdx_package_id, reference_category, reference_type, reference_locator
				) VALUES (?, ?, ?, ?, ?, ?, ?)
			`, runUUID, sbomID, depID, pkg.GetSPDXID(), ref.ReferenceCategory, ref.ReferenceType, ref.ReferenceLocator)
			if err != nil {
				return err
			}
		}
	}

	for _, described := range doc.DocumentDescribes {
		if strings.TrimSpace(described) == "" {
			continue
		}
		if _, err := tx.Exec(`
			INSERT OR IGNORE INTO sbom_document_describes(run_uuid, sbom_id, spdx_element_id)
			VALUES (?, ?, ?)
		`, runUUID, sbomID, described); err != nil {
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
			INSERT OR IGNORE INTO sbom_relationships(
				run_uuid, sbom_id, from_dependency_id, to_dependency_id, relationship_type, from_spdx_id, to_spdx_id
			)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, runUUID, sbomID, nullableInt64(okFrom, fromID), nullableInt64(okTo, toID), rel.RelationshipType, rel.SPDXElementID, rel.RelatedSPDXElement)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func upsertDependencyTx(tx *sql.Tx, ecosystem, name, version, purl, license, supplier, licenseDeclared, downloadLocation string, filesAnalyzed interface{}) (int64, error) {
	_, err := tx.Exec(`
		INSERT OR IGNORE INTO dependencies(
			ecosystem, name, version, purl, license, supplier, license_declared, download_location, files_analyzed
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, safeStr(ecosystem), safeStr(name), safeStr(version), safeStr(purl), license, supplier, licenseDeclared, downloadLocation, filesAnalyzed)
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

	_, err = tx.Exec(`
		UPDATE dependencies
		SET
			license = COALESCE(NULLIF(?, ''), license),
			supplier = COALESCE(NULLIF(?, ''), supplier),
			license_declared = COALESCE(NULLIF(?, ''), license_declared),
			download_location = COALESCE(NULLIF(?, ''), download_location),
			files_analyzed = COALESCE(?, files_analyzed)
		WHERE dependency_id = ?
	`, license, supplier, licenseDeclared, downloadLocation, filesAnalyzed, depID)
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
		after := ""
		for {
			opts := &github.ListAlertsOptions{
				State: stringPtr(state),
				ListCursorOptions: github.ListCursorOptions{
					PerPage: perPage,
					After:   after,
				},
			}
			alerts, resp, err := client.Dependabot.ListOrgAlerts(ctx, org, opts)
			if err != nil {
				return nil, pageCount, fmt.Errorf("dependabot org alerts fetch failed (org=%s state=%s after=%q): %w", org, state, after, err)
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
			log.Printf("dependabot page fetched: state=%s after=%q items=%d added=%d total=%d", state, after, len(alerts), added, len(all))
			if resp.After == "" {
				break
			}
			after = resp.After
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
			manifest_path, created_at, updated_at, fixed_at, dismissed_reason, dependency_id,
			url, html_url, dismissed_at, dismissed_comment, auto_dismissed_at, dependency_scope, advisory_ghsa_id, advisory_cve_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
			dependency_id = excluded.dependency_id,
			url = excluded.url,
			html_url = excluded.html_url,
			dismissed_at = excluded.dismissed_at,
			dismissed_comment = excluded.dismissed_comment,
			auto_dismissed_at = excluded.auto_dismissed_at,
			dependency_scope = excluded.dependency_scope,
			advisory_ghsa_id = excluded.advisory_ghsa_id,
			advisory_cve_id = excluded.advisory_cve_id
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
			a.GetURL(),
			a.GetHTMLURL(),
			formatGitHubTimePtr(a.DismissedAt),
			a.GetDismissedComment(),
			formatGitHubTimePtr(a.AutoDismissedAt),
			dependency.GetScope(),
			securityAdv.GetGHSAID(),
			securityAdv.GetCVEID(),
		)
		if err != nil {
			return err
		}
		if err := upsertDependabotAdvisoryTx(tx, runUUID, repoID, a); err != nil {
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
			most_recent_end_column, most_recent_state, most_recent_category, most_recent_classifications,
			updated_at, closed_at, url, html_url, instances_url, dismissed_at, dismissed_reason, dismissed_comment,
			rule_description, tool_guid, tool_version, most_recent_analysis_key, most_recent_environment
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
			most_recent_classifications = excluded.most_recent_classifications,
			updated_at = excluded.updated_at,
			closed_at = excluded.closed_at,
			url = excluded.url,
			html_url = excluded.html_url,
			instances_url = excluded.instances_url,
			dismissed_at = excluded.dismissed_at,
			dismissed_reason = excluded.dismissed_reason,
			dismissed_comment = excluded.dismissed_comment,
			rule_description = excluded.rule_description,
			tool_guid = excluded.tool_guid,
			tool_version = excluded.tool_version,
			most_recent_analysis_key = excluded.most_recent_analysis_key,
			most_recent_environment = excluded.most_recent_environment
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
		toolGUID := ""
		toolVersion := ""
		if tool := a.GetTool(); tool != nil {
			toolName = tool.GetName()
			toolGUID = tool.GetGUID()
			toolVersion = tool.GetVersion()
		}
		ruleID := ""
		securitySeverity := ""
		ruleDescription := ""
		if rule := a.GetRule(); rule != nil {
			ruleID = rule.GetID()
			securitySeverity = rule.GetSecuritySeverityLevel()
			ruleDescription = firstNonEmpty(rule.GetDescription(), a.GetRuleDescription())
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
			formatGitHubTimePtr(a.UpdatedAt),
			formatGitHubTimePtr(a.ClosedAt),
			a.GetURL(),
			a.GetHTMLURL(),
			a.GetInstancesURL(),
			formatGitHubTimePtr(a.DismissedAt),
			a.GetDismissedReason(),
			a.GetDismissedComment(),
			ruleDescription,
			toolGUID,
			toolVersion,
			mostRecentAnalysisKey(a.GetMostRecentInstance()),
			mostRecentEnvironment(a.GetMostRecentInstance()),
		)
		if err != nil {
			return err
		}
		if err := upsertCodeScanningRuleTagsTx(tx, runUUID, repoID, a); err != nil {
			return err
		}
		if err := upsertCodeScanningInstancesTx(tx, runUUID, repoID, a); err != nil {
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
			run_uuid, repo_id, alert_number, state, secret_type, resolution, created_at, updated_at, resolved_at,
			url, html_url, locations_url, secret_type_display_name, secret, is_base64_encoded, multi_repo, publicly_leaked,
			push_protection_bypassed, push_protection_bypassed_by_login, push_protection_bypassed_by_id,
			push_protection_bypassed_at, resolution_comment, push_protection_bypass_request_comment,
			push_protection_bypass_request_html_url, push_protection_bypass_request_reviewer_login,
			push_protection_bypass_request_reviewer_id, validity, has_more_locations
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(run_uuid, repo_id, alert_number) DO UPDATE SET
			state = excluded.state,
			secret_type = excluded.secret_type,
			resolution = excluded.resolution,
			created_at = excluded.created_at,
			updated_at = excluded.updated_at,
			resolved_at = excluded.resolved_at,
			url = excluded.url,
			html_url = excluded.html_url,
			locations_url = excluded.locations_url,
			secret_type_display_name = excluded.secret_type_display_name,
			secret = excluded.secret,
			is_base64_encoded = excluded.is_base64_encoded,
			multi_repo = excluded.multi_repo,
			publicly_leaked = excluded.publicly_leaked,
			push_protection_bypassed = excluded.push_protection_bypassed,
			push_protection_bypassed_by_login = excluded.push_protection_bypassed_by_login,
			push_protection_bypassed_by_id = excluded.push_protection_bypassed_by_id,
			push_protection_bypassed_at = excluded.push_protection_bypassed_at,
			resolution_comment = excluded.resolution_comment,
			push_protection_bypass_request_comment = excluded.push_protection_bypass_request_comment,
			push_protection_bypass_request_html_url = excluded.push_protection_bypass_request_html_url,
			push_protection_bypass_request_reviewer_login = excluded.push_protection_bypass_request_reviewer_login,
			push_protection_bypass_request_reviewer_id = excluded.push_protection_bypass_request_reviewer_id,
			validity = excluded.validity,
			has_more_locations = excluded.has_more_locations
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
			a.GetURL(),
			a.GetHTMLURL(),
			a.GetLocationsURL(),
			a.GetSecretTypeDisplayName(),
			a.GetSecret(),
			boolPtrToIntPtr(a.IsBase64Encoded),
			boolPtrToIntPtr(a.MultiRepo),
			boolPtrToIntPtr(a.PubliclyLeaked),
			boolPtrToIntPtr(a.PushProtectionBypassed),
			a.GetPushProtectionBypassedBy().GetLogin(),
			nullableInt64Value(a.GetPushProtectionBypassedBy().GetID()),
			formatGitHubTimePtr(a.PushProtectionBypassedAt),
			a.GetResolutionComment(),
			a.GetPushProtectionBypassRequestComment(),
			a.GetPushProtectionBypassRequestHTMLURL(),
			a.GetPushProtectionBypassRequestReviewer().GetLogin(),
			nullableInt64Value(a.GetPushProtectionBypassRequestReviewer().GetID()),
			a.GetValidity(),
			boolPtrToIntPtr(a.HasMoreLocations),
		)
		if err != nil {
			return err
		}
		if err := upsertSecretScanningFirstLocationTx(tx, runUUID, repoID, a); err != nil {
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
			bypass_actor_count, current_user_can_bypass, node_id, created_at, updated_at, ref_name_includes, ref_name_excludes,
			rules_count, conditions_json, rules_json, links_self_href, links_html_href
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
			ref_name_excludes = excluded.ref_name_excludes,
			rules_count = excluded.rules_count,
			conditions_json = excluded.conditions_json,
			rules_json = excluded.rules_json,
			links_self_href = excluded.links_self_href,
			links_html_href = excluded.links_html_href
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
		conditionsJSON := jsonString(rs.Conditions)
		rulesJSON := jsonString(rs.Rules)
		linksSelf := ""
		linksHTML := ""
		if rs.Links != nil {
			if rs.Links.Self != nil {
				linksSelf = rs.Links.Self.GetHRef()
			}
			if rs.Links.HTML != nil {
				linksHTML = rs.Links.HTML.GetHRef()
			}
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
			countRulesetRules(rs.Rules),
			conditionsJSON,
			rulesJSON,
			linksSelf,
			linksHTML,
		)
		if err != nil {
			return err
		}
		if err := upsertRulesetChildrenTx(tx, runUUID, repoID, rs); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func upsertDependabotAdvisoryTx(tx *sql.Tx, runUUID string, repoID int64, a *github.DependabotAlert) error {
	if a == nil {
		return nil
	}
	alertNumber := a.GetNumber()
	adv := a.GetSecurityAdvisory()

	_, err := tx.Exec(`
		INSERT INTO dependabot_security_advisories(
			run_uuid, repo_id, alert_number, ghsa_id, cve_id, summary, description, severity,
			cvss_score, cvss_vector_string, epss_percentage, epss_percentile, published_at, updated_at, withdrawn_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(run_uuid, repo_id, alert_number) DO UPDATE SET
			ghsa_id = excluded.ghsa_id,
			cve_id = excluded.cve_id,
			summary = excluded.summary,
			description = excluded.description,
			severity = excluded.severity,
			cvss_score = excluded.cvss_score,
			cvss_vector_string = excluded.cvss_vector_string,
			epss_percentage = excluded.epss_percentage,
			epss_percentile = excluded.epss_percentile,
			published_at = excluded.published_at,
			updated_at = excluded.updated_at,
			withdrawn_at = excluded.withdrawn_at
	`,
		runUUID, repoID, alertNumber, adv.GetGHSAID(), adv.GetCVEID(), adv.GetSummary(), adv.GetDescription(), adv.GetSeverity(),
		floatPtrToValue(adv.CVSS.GetScore()), adv.CVSS.GetVectorString(), epssPercentageValue(adv.EPSS), epssPercentileValue(adv.EPSS),
		formatGitHubTimePtr(adv.PublishedAt), formatGitHubTimePtr(adv.UpdatedAt), formatGitHubTimePtr(adv.WithdrawnAt),
	)
	if err != nil {
		return err
	}

	for _, table := range []string{
		"dependabot_advisory_vulnerabilities",
		"dependabot_advisory_identifiers",
		"dependabot_advisory_references",
		"dependabot_advisory_cwes",
	} {
		if _, err := tx.Exec(
			fmt.Sprintf("DELETE FROM %s WHERE run_uuid = ? AND repo_id = ? AND alert_number = ?", table),
			runUUID, repoID, alertNumber,
		); err != nil {
			return err
		}
	}

	for i, v := range adv.Vulnerabilities {
		if v == nil {
			continue
		}
		_, err := tx.Exec(`
			INSERT INTO dependabot_advisory_vulnerabilities(
				run_uuid, repo_id, alert_number, row_num, ecosystem, package_name, severity, vulnerable_version_range,
				first_patched_version, patched_versions, vulnerable_functions
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, runUUID, repoID, alertNumber, i+1, v.GetPackage().GetEcosystem(), v.GetPackage().GetName(), v.GetSeverity(),
			v.GetVulnerableVersionRange(), v.GetFirstPatchedVersion().GetIdentifier(), v.GetPatchedVersions(), strings.Join(v.VulnerableFunctions, ","))
		if err != nil {
			return err
		}
	}

	for i, id := range adv.Identifiers {
		if id == nil {
			continue
		}
		_, err := tx.Exec(`
			INSERT INTO dependabot_advisory_identifiers(run_uuid, repo_id, alert_number, row_num, value, type)
			VALUES (?, ?, ?, ?, ?, ?)
		`, runUUID, repoID, alertNumber, i+1, id.GetValue(), id.GetType())
		if err != nil {
			return err
		}
	}

	for i, ref := range adv.References {
		if ref == nil {
			continue
		}
		_, err := tx.Exec(`
			INSERT INTO dependabot_advisory_references(run_uuid, repo_id, alert_number, row_num, url)
			VALUES (?, ?, ?, ?, ?)
		`, runUUID, repoID, alertNumber, i+1, ref.GetURL())
		if err != nil {
			return err
		}
	}

	for i, cwe := range adv.CWEs {
		if cwe == nil {
			continue
		}
		_, err := tx.Exec(`
			INSERT INTO dependabot_advisory_cwes(run_uuid, repo_id, alert_number, row_num, cwe_id, name)
			VALUES (?, ?, ?, ?, ?, ?)
		`, runUUID, repoID, alertNumber, i+1, cwe.GetCWEID(), cwe.GetName())
		if err != nil {
			return err
		}
	}

	return nil
}

func upsertCodeScanningRuleTagsTx(tx *sql.Tx, runUUID string, repoID int64, a *github.Alert) error {
	if a == nil {
		return nil
	}
	alertNumber := a.GetNumber()
	if _, err := tx.Exec(`DELETE FROM code_scanning_rule_tags WHERE run_uuid = ? AND repo_id = ? AND alert_number = ?`, runUUID, repoID, alertNumber); err != nil {
		return err
	}
	rule := a.GetRule()
	for i, tag := range rule.Tags {
		if strings.TrimSpace(tag) == "" {
			continue
		}
		if _, err := tx.Exec(`
			INSERT INTO code_scanning_rule_tags(run_uuid, repo_id, alert_number, row_num, tag)
			VALUES (?, ?, ?, ?, ?)
		`, runUUID, repoID, alertNumber, i+1, tag); err != nil {
			return err
		}
	}
	return nil
}

func upsertCodeScanningInstancesTx(tx *sql.Tx, runUUID string, repoID int64, a *github.Alert) error {
	if a == nil {
		return nil
	}
	alertNumber := a.GetNumber()
	if _, err := tx.Exec(`DELETE FROM code_scanning_alert_instances WHERE run_uuid = ? AND repo_id = ? AND alert_number = ?`, runUUID, repoID, alertNumber); err != nil {
		return err
	}
	for i, inst := range a.Instances {
		if inst == nil {
			continue
		}
		var startLine, endLine, startColumn, endColumn interface{}
		path := ""
		if inst.Location != nil {
			path = inst.Location.GetPath()
			startLine = nullableIntPtr(inst.Location.StartLine)
			endLine = nullableIntPtr(inst.Location.EndLine)
			startColumn = nullableIntPtr(inst.Location.StartColumn)
			endColumn = nullableIntPtr(inst.Location.EndColumn)
		}
		_, err := tx.Exec(`
			INSERT INTO code_scanning_alert_instances(
				run_uuid, repo_id, alert_number, row_num, ref, analysis_key, category, environment, state,
				commit_sha, message_text, path, start_line, end_line, start_column, end_column
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, runUUID, repoID, alertNumber, i+1, inst.GetRef(), inst.GetAnalysisKey(), inst.GetCategory(), inst.GetEnvironment(), inst.GetState(),
			inst.GetCommitSHA(), inst.GetMessage().GetText(), path, startLine, endLine, startColumn, endColumn)
		if err != nil {
			return err
		}
	}
	return nil
}

func upsertSecretScanningFirstLocationTx(tx *sql.Tx, runUUID string, repoID int64, a *github.SecretScanningAlert) error {
	if a == nil {
		return nil
	}
	loc := a.GetFirstLocationDetected()
	_, err := tx.Exec(`
		INSERT INTO secret_scanning_first_locations(
			run_uuid, repo_id, alert_number, path, start_line, end_line, start_column, end_column,
			blob_sha, blob_url, commit_sha, commit_url, pull_request_comment_url
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(run_uuid, repo_id, alert_number) DO UPDATE SET
			path = excluded.path,
			start_line = excluded.start_line,
			end_line = excluded.end_line,
			start_column = excluded.start_column,
			end_column = excluded.end_column,
			blob_sha = excluded.blob_sha,
			blob_url = excluded.blob_url,
			commit_sha = excluded.commit_sha,
			commit_url = excluded.commit_url,
			pull_request_comment_url = excluded.pull_request_comment_url
	`, runUUID, repoID, a.GetNumber(), loc.GetPath(), nullableIntPtr(loc.Startline), nullableIntPtr(loc.EndLine), nullableIntPtr(loc.StartColumn), nullableIntPtr(loc.EndColumn),
		loc.GetBlobSHA(), loc.GetBlobURL(), loc.GetCommitSHA(), loc.GetCommitURL(), loc.GetPullRequestCommentURL())
	return err
}

type rulesetRuleEntry struct {
	RuleType       string
	ParametersJSON string
}

func rulesetRuleEntries(rules *github.RepositoryRulesetRules) []rulesetRuleEntry {
	if rules == nil {
		return nil
	}
	raw, err := json.Marshal(rules)
	if err != nil || len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	entries := make([]rulesetRuleEntry, 0)
	if raw[0] == '[' {
		var list []map[string]interface{}
		if err := json.Unmarshal(raw, &list); err != nil {
			return nil
		}
		for _, item := range list {
			ruleType := stringifyAny(item["type"])
			params := jsonString(item["parameters"])
			entries = append(entries, rulesetRuleEntry{RuleType: ruleType, ParametersJSON: params})
		}
		return entries
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil
	}
	for k, v := range obj {
		entries = append(entries, rulesetRuleEntry{RuleType: k, ParametersJSON: jsonString(v)})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].RuleType < entries[j].RuleType })
	return entries
}

func countRulesetRules(rules *github.RepositoryRulesetRules) int {
	return len(rulesetRuleEntries(rules))
}

func upsertRulesetChildrenTx(tx *sql.Tx, runUUID string, repoID int64, rs *github.RepositoryRuleset) error {
	if rs == nil {
		return nil
	}
	rulesetID := rs.GetID()
	for _, table := range []string{
		"repo_ruleset_bypass_actors",
		"repo_ruleset_rule_entries",
		"repo_ruleset_condition_repo_ids",
		"repo_ruleset_condition_repo_names",
		"repo_ruleset_condition_org_ids",
		"repo_ruleset_condition_org_names",
		"repo_ruleset_condition_property_targets",
	} {
		if _, err := tx.Exec(fmt.Sprintf("DELETE FROM %s WHERE run_uuid = ? AND repo_id = ? AND ruleset_id = ?", table), runUUID, repoID, rulesetID); err != nil {
			return err
		}
	}

	for i, actor := range rs.BypassActors {
		if actor == nil {
			continue
		}
		if _, err := tx.Exec(`
			INSERT INTO repo_ruleset_bypass_actors(run_uuid, repo_id, ruleset_id, row_num, actor_id, actor_type, bypass_mode)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, runUUID, repoID, rulesetID, i+1, nullableInt64Value(actor.GetActorID()), stringValue(actor.ActorType), stringValue(actor.BypassMode)); err != nil {
			return err
		}
	}

	linksSelf := ""
	linksHTML := ""
	if rs.Links != nil {
		if rs.Links.Self != nil {
			linksSelf = rs.Links.Self.GetHRef()
		}
		if rs.Links.HTML != nil {
			linksHTML = rs.Links.HTML.GetHRef()
		}
	}
	if _, err := tx.Exec(`
		INSERT INTO repo_ruleset_links(run_uuid, repo_id, ruleset_id, self_href, html_href)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(run_uuid, repo_id, ruleset_id) DO UPDATE SET
			self_href = excluded.self_href,
			html_href = excluded.html_href
	`, runUUID, repoID, rulesetID, linksSelf, linksHTML); err != nil {
		return err
	}

	for i, entry := range rulesetRuleEntries(rs.Rules) {
		if _, err := tx.Exec(`
			INSERT INTO repo_ruleset_rule_entries(run_uuid, repo_id, ruleset_id, row_num, rule_type, parameters_json)
			VALUES (?, ?, ?, ?, ?, ?)
		`, runUUID, repoID, rulesetID, i+1, entry.RuleType, entry.ParametersJSON); err != nil {
			return err
		}
	}

	conds := rs.Conditions
	if conds == nil {
		return nil
	}
	if conds.RepositoryID != nil {
		for _, id := range conds.RepositoryID.RepositoryIDs {
			if _, err := tx.Exec(`
				INSERT INTO repo_ruleset_condition_repo_ids(run_uuid, repo_id, ruleset_id, repository_id)
				VALUES (?, ?, ?, ?)
			`, runUUID, repoID, rulesetID, id); err != nil {
				return err
			}
		}
	}
	if conds.RepositoryName != nil {
		for _, v := range conds.RepositoryName.Include {
			if _, err := tx.Exec(`
				INSERT INTO repo_ruleset_condition_repo_names(run_uuid, repo_id, ruleset_id, include_exclude, repo_name)
				VALUES (?, ?, ?, 'include', ?)
			`, runUUID, repoID, rulesetID, v); err != nil {
				return err
			}
		}
		for _, v := range conds.RepositoryName.Exclude {
			if _, err := tx.Exec(`
				INSERT INTO repo_ruleset_condition_repo_names(run_uuid, repo_id, ruleset_id, include_exclude, repo_name)
				VALUES (?, ?, ?, 'exclude', ?)
			`, runUUID, repoID, rulesetID, v); err != nil {
				return err
			}
		}
	}
	if conds.OrganizationID != nil {
		for _, id := range conds.OrganizationID.OrganizationIDs {
			if _, err := tx.Exec(`
				INSERT INTO repo_ruleset_condition_org_ids(run_uuid, repo_id, ruleset_id, organization_id)
				VALUES (?, ?, ?, ?)
			`, runUUID, repoID, rulesetID, id); err != nil {
				return err
			}
		}
	}
	if conds.OrganizationName != nil {
		for _, v := range conds.OrganizationName.Include {
			if _, err := tx.Exec(`
				INSERT INTO repo_ruleset_condition_org_names(run_uuid, repo_id, ruleset_id, include_exclude, organization_name)
				VALUES (?, ?, ?, 'include', ?)
			`, runUUID, repoID, rulesetID, v); err != nil {
				return err
			}
		}
		for _, v := range conds.OrganizationName.Exclude {
			if _, err := tx.Exec(`
				INSERT INTO repo_ruleset_condition_org_names(run_uuid, repo_id, ruleset_id, include_exclude, organization_name)
				VALUES (?, ?, ?, 'exclude', ?)
			`, runUUID, repoID, rulesetID, v); err != nil {
				return err
			}
		}
	}

	if err := insertPropertyTargetsTx(tx, runUUID, repoID, rulesetID, "repository", conds.RepositoryProperty); err != nil {
		return err
	}
	if err := insertPropertyTargetsTx(tx, runUUID, repoID, rulesetID, "organization", conds.OrganizationProperty); err != nil {
		return err
	}

	return nil
}

func insertPropertyTargetsTx(tx *sql.Tx, runUUID string, repoID, rulesetID int64, scope string, raw interface{}) error {
	var include []*github.RepositoryRulesetRepositoryPropertyTargetParameters
	var exclude []*github.RepositoryRulesetRepositoryPropertyTargetParameters
	switch prop := raw.(type) {
	case *github.RepositoryRulesetRepositoryPropertyConditionParameters:
		if prop == nil {
			return nil
		}
		include = prop.Include
		exclude = prop.Exclude
	case *github.RepositoryRulesetOrganizationPropertyConditionParameters:
		if prop == nil {
			return nil
		}
		include = prop.Include
		exclude = prop.Exclude
	default:
		return nil
	}
	for _, t := range include {
		if t == nil {
			continue
		}
		if _, err := tx.Exec(`
			INSERT INTO repo_ruleset_condition_property_targets(
				run_uuid, repo_id, ruleset_id, target_scope, include_exclude, name, property_values, source
			) VALUES (?, ?, ?, ?, 'include', ?, ?, ?)
		`, runUUID, repoID, rulesetID, scope, t.Name, strings.Join(t.PropertyValues, ","), t.GetSource()); err != nil {
			return err
		}
	}
	for _, t := range exclude {
		if t == nil {
			continue
		}
		if _, err := tx.Exec(`
			INSERT INTO repo_ruleset_condition_property_targets(
				run_uuid, repo_id, ruleset_id, target_scope, include_exclude, name, property_values, source
			) VALUES (?, ?, ?, ?, 'exclude', ?, ?, ?)
		`, runUUID, repoID, rulesetID, scope, t.Name, strings.Join(t.PropertyValues, ","), t.GetSource()); err != nil {
			return err
		}
	}
	return nil
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

func boolPtrToIntPtr(v *bool) interface{} {
	if v == nil {
		return nil
	}
	if *v {
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

func nullableInt64Value(v int64) interface{} {
	if v == 0 {
		return nil
	}
	return v
}

func nullableIntPtr(v *int) interface{} {
	if v == nil {
		return nil
	}
	return *v
}

func floatPtrToValue(v *float64) interface{} {
	if v == nil {
		return nil
	}
	return *v
}

func epssPercentageValue(e *github.AdvisoryEPSS) interface{} {
	if e == nil {
		return nil
	}
	return e.Percentage
}

func epssPercentileValue(e *github.AdvisoryEPSS) interface{} {
	if e == nil {
		return nil
	}
	return e.Percentile
}

func mostRecentAnalysisKey(inst *github.MostRecentInstance) string {
	if inst == nil {
		return ""
	}
	return inst.GetAnalysisKey()
}

func mostRecentEnvironment(inst *github.MostRecentInstance) string {
	if inst == nil {
		return ""
	}
	return inst.GetEnvironment()
}

func jsonString(v interface{}) string {
	if v == nil {
		return ""
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	if string(b) == "null" {
		return ""
	}
	return string(b)
}

func stringifyAny(v interface{}) string {
	if v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	default:
		return fmt.Sprintf("%v", x)
	}
}

func stringValue[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
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
