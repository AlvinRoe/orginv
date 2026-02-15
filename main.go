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

type config struct {
	Org            string
	Token          string
	ResultsPerPage int
	SQLitePath     string
	CSVOutputPath  string
}

type dependabotAlert struct {
	Number                int64     `json:"number"`
	State                 string    `json:"state"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
	FixedAt               time.Time `json:"fixed_at"`
	Dismissed             string    `json:"dismissed_reason"`
	SecurityVulnerability struct {
		Severity string `json:"severity"`
		Package  struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
	} `json:"security_vulnerability"`
	Dependency struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		ManifestPath string `json:"manifest_path"`
	} `json:"dependency"`
	Repository struct {
		ID       int64  `json:"id"`
		Name     string `json:"name"`
		FullName string `json:"full_name"`
	} `json:"repository"`
}

type codeScanningAlert struct {
	Number                int64     `json:"number"`
	State                 string    `json:"state"`
	CreatedAt             time.Time `json:"created_at"`
	FixedAt               time.Time `json:"fixed_at"`
	Severity              string    `json:"severity"`
	SecuritySeverityLevel string    `json:"security_severity_level"`
	Rule                  struct {
		ID string `json:"id"`
	} `json:"rule"`
	Tool struct {
		Name string `json:"name"`
	} `json:"tool"`
	MostRecentInstance json.RawMessage `json:"most_recent_instance"`
	Repository         struct {
		ID       int64  `json:"id"`
		Name     string `json:"name"`
		FullName string `json:"full_name"`
	} `json:"repository"`
}

type secretScanningAlert struct {
	Number     int64     `json:"number"`
	State      string    `json:"state"`
	SecretType string    `json:"secret_type"`
	Resolution string    `json:"resolution"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	ResolvedAt time.Time `json:"resolved_at"`
	Repository struct {
		ID       int64  `json:"id"`
		Name     string `json:"name"`
		FullName string `json:"full_name"`
	} `json:"repository"`
}

type repoRuleset struct {
	ID          int64           `json:"id"`
	Enforcement string          `json:"enforcement"`
	Target      string          `json:"target"`
	Raw         json.RawMessage `json:"-"`
}

type spdxDocument struct {
	SPDXVersion  string `json:"spdxVersion"`
	CreationInfo struct {
		Created string `json:"created"`
	} `json:"creationInfo"`
	Packages      []spdxPackage `json:"packages"`
	Relationships []struct {
		SpdxElementID      string `json:"spdxElementId"`
		RelationshipType   string `json:"relationshipType"`
		RelatedSpdxElement string `json:"relatedSpdxElement"`
	} `json:"relationships"`
}

type spdxPackage struct {
	SPDXID           string      `json:"SPDXID"`
	Name             string      `json:"name"`
	VersionInfo      string      `json:"versionInfo"`
	LicenseConcluded string      `json:"licenseConcluded"`
	Supplier         interface{} `json:"supplier"`
	ExternalRefs     []struct {
		ReferenceType    string `json:"referenceType"`
		ReferenceLocator string `json:"referenceLocator"`
	} `json:"externalRefs"`
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

	orgInfo, _, err := client.Organizations.Get(ctx, cfg.Org)
	if err != nil {
		log.Printf("warning: failed to fetch org metadata: %v", err)
	}
	if err := upsertOrg(db, runUUID, cfg.Org, orgInfo); err != nil {
		log.Fatalf("failed to upsert org: %v", err)
	}

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

	log.Printf("ingesting org-level alert datasets")
	if err := ingestDependabotAlerts(ctx, client, db, runUUID, cfg.Org, cfg.ResultsPerPage, repoIDByName); err != nil {
		recordErr("dependabot ingestion failed", err)
	}
	if err := ingestCodeScanningAlerts(ctx, client, db, runUUID, cfg.Org, cfg.ResultsPerPage, repoIDByName); err != nil {
		recordErr("code scanning ingestion failed", err)
	}
	if err := ingestSecretScanningAlerts(ctx, client, db, runUUID, cfg.Org, cfg.ResultsPerPage, repoIDByName); err != nil {
		recordErr("secret scanning ingestion failed", err)
	}

	log.Printf("ingesting per-repo datasets (sbom, rulesets, workflow runs)")
	const repoWorkers = 10
	repoChan := make(chan *github.Repository, len(activeRepos))
	var wg sync.WaitGroup

	var dbMu sync.Mutex
	for i := 0; i < repoWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for repo := range repoChan {
				repoName := repo.GetName()
				repoID := repo.GetID()

				sbom, _, sbomErr := client.DependencyGraph.GetSBOM(ctx, cfg.Org, repoName)
				if sbomErr != nil {
					recordErr(fmt.Sprintf("worker %d sbom %s", workerID, repoName), sbomErr)
				} else {
					dbMu.Lock()
					if err := ingestSBOM(db, runUUID, repoID, sbom); err != nil {
						recordErr(fmt.Sprintf("worker %d ingest sbom %s", workerID, repoName), err)
					}
					dbMu.Unlock()
				}

				rulesets, rErr := fetchRepoRulesets(ctx, client, cfg.Org, repoName, cfg.ResultsPerPage)
				if rErr != nil {
					recordErr(fmt.Sprintf("worker %d rulesets %s", workerID, repoName), rErr)
				} else {
					dbMu.Lock()
					if err := ingestRepoRulesets(db, runUUID, repoID, rulesets); err != nil {
						recordErr(fmt.Sprintf("worker %d ingest rulesets %s", workerID, repoName), err)
					}
					dbMu.Unlock()
				}

				runs, wErr := fetchWorkflowRuns(ctx, client, cfg.Org, repoName, cfg.ResultsPerPage)
				if wErr != nil {
					recordErr(fmt.Sprintf("worker %d workflow runs %s", workerID, repoName), wErr)
				} else {
					dbMu.Lock()
					if err := ingestWorkflowRuns(db, runUUID, repoID, runs); err != nil {
						recordErr(fmt.Sprintf("worker %d ingest workflow runs %s", workerID, repoName), err)
					}
					dbMu.Unlock()
				}
			}
		}(i + 1)
	}

	for _, repo := range activeRepos {
		repoChan <- repo
	}
	close(repoChan)
	wg.Wait()

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
		`CREATE TABLE IF NOT EXISTS orgs (
			run_uuid TEXT NOT NULL,
			org_id INTEGER,
			login TEXT NOT NULL,
			name TEXT,
			snapshot_at TEXT NOT NULL,
			PRIMARY KEY (run_uuid, login)
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
			created_at TEXT,
			updated_at TEXT,
			pushed_at TEXT,
			metadata_json TEXT,
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
			spdx_version TEXT,
			generated_at TEXT,
			raw_json TEXT NOT NULL,
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
			most_recent_instance_json TEXT,
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
			enforcement TEXT,
			target TEXT,
			raw_json TEXT,
			PRIMARY KEY (run_uuid, repo_id, ruleset_id)
		);`,
		`CREATE TABLE IF NOT EXISTS workflow_runs (
			run_uuid TEXT NOT NULL,
			repo_id INTEGER NOT NULL,
			run_id INTEGER NOT NULL,
			workflow_name TEXT,
			status TEXT,
			conclusion TEXT,
			run_started_at TEXT,
			updated_at TEXT,
			PRIMARY KEY (run_uuid, repo_id, run_id)
		);`,
	}

	for _, stmt := range schema {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func startIngestionRun(db *sql.DB, runUUID string) error {
	_, err := db.Exec(`INSERT INTO ingestion_runs(run_uuid, started_at, status) VALUES (?, ?, ?)`, runUUID, time.Now().UTC().Format(time.RFC3339), "running")
	return err
}

func finishIngestionRun(db *sql.DB, runUUID, status, summary string) error {
	_, err := db.Exec(`UPDATE ingestion_runs SET finished_at = ?, status = ?, error_summary = ? WHERE run_uuid = ?`, time.Now().UTC().Format(time.RFC3339), status, summary, runUUID)
	return err
}

func upsertOrg(db *sql.DB, runUUID, org string, orgInfo *github.Organization) error {
	orgID := int64(0)
	name := ""
	if orgInfo != nil {
		orgID = orgInfo.GetID()
		name = orgInfo.GetName()
	}
	_, err := db.Exec(`
		INSERT INTO orgs(run_uuid, org_id, login, name, snapshot_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(run_uuid, login) DO UPDATE SET org_id = excluded.org_id, name = excluded.name, snapshot_at = excluded.snapshot_at
	`, runUUID, orgID, org, name, time.Now().UTC().Format(time.RFC3339))
	return err
}

func upsertRepo(db *sql.DB, runUUID, org string, repo *github.Repository) error {
	meta, err := json.Marshal(repo)
	if err != nil {
		return err
	}
	_, err = db.Exec(`
		INSERT INTO repos(
			run_uuid, repo_id, org_login, name, full_name, visibility, private, archived, disabled,
			default_branch, language, open_issues_count, created_at, updated_at, pushed_at, metadata_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
			created_at = excluded.created_at,
			updated_at = excluded.updated_at,
			pushed_at = excluded.pushed_at,
			metadata_json = excluded.metadata_json
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
		formatGitHubTimePtr(repo.CreatedAt),
		formatGitHubTimePtr(repo.UpdatedAt),
		formatGitHubTimePtr(repo.PushedAt),
		string(meta),
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
	raw, err := json.Marshal(sbom)
	if err != nil {
		return err
	}

	doc := spdxDocument{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec(`
		INSERT INTO sbom_documents(run_uuid, repo_id, spdx_version, generated_at, raw_json)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(run_uuid, repo_id) DO UPDATE SET
			spdx_version = excluded.spdx_version,
			generated_at = excluded.generated_at,
			raw_json = excluded.raw_json
	`, runUUID, repoID, doc.SPDXVersion, doc.CreationInfo.Created, string(raw))
	if err != nil {
		return err
	}

	var sbomID int64
	if err := tx.QueryRow(`SELECT sbom_id FROM sbom_documents WHERE run_uuid = ? AND repo_id = ?`, runUUID, repoID).Scan(&sbomID); err != nil {
		return err
	}

	pkgIDMap := make(map[string]int64, len(doc.Packages))
	for _, pkg := range doc.Packages {
		purl := extractPURL(pkg)
		ecosystem := ecosystemFromPURL(purl)
		if ecosystem == "" {
			ecosystem = "unknown"
		}
		depID, err := upsertDependencyTx(tx, ecosystem, pkg.Name, pkg.VersionInfo, purl, pkg.LicenseConcluded, supplierToString(pkg.Supplier))
		if err != nil {
			return err
		}
		pkgIDMap[pkg.SPDXID] = depID
		if _, err := tx.Exec(`
			INSERT OR IGNORE INTO repo_dependencies(run_uuid, repo_id, dependency_id, source, snapshot_at)
			VALUES (?, ?, ?, ?, ?)
		`, runUUID, repoID, depID, "sbom", time.Now().UTC().Format(time.RFC3339)); err != nil {
			return err
		}
	}

	for _, rel := range doc.Relationships {
		fromID, okFrom := pkgIDMap[rel.SpdxElementID]
		toID, okTo := pkgIDMap[rel.RelatedSpdxElement]
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

func ingestDependabotAlerts(ctx context.Context, client *github.Client, db *sql.DB, runUUID, org string, perPage int, repoIDByName map[string]int64) error {
	alerts, err := fetchPaginated(ctx, client, fmt.Sprintf("orgs/%s/dependabot/alerts", org), perPage, func() interface{} {
		return &[]dependabotAlert{}
	})
	if err != nil {
		return err
	}

	typed := alerts.([]dependabotAlert)
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, a := range typed {
		repoID, ok := resolveRepoID(repoIDByName, a.Repository.FullName, a.Repository.Name)
		if !ok {
			continue
		}
		ecosystem := firstNonEmpty(a.Dependency.Package.Ecosystem, a.SecurityVulnerability.Package.Ecosystem)
		pkgName := firstNonEmpty(a.Dependency.Package.Name, a.SecurityVulnerability.Package.Name)
		severity := strings.ToLower(a.SecurityVulnerability.Severity)

		depIDPtr, depErr := lookupDependencyIDTx(tx, ecosystem, pkgName)
		if depErr != nil {
			return depErr
		}

		_, err := tx.Exec(`
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
		`, runUUID, repoID, a.Number, a.State, severity, ecosystem, pkgName,
			a.Dependency.ManifestPath, formatTime(a.CreatedAt), formatTime(a.UpdatedAt), formatTime(a.FixedAt), a.Dismissed, depIDPtr)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func ingestCodeScanningAlerts(ctx context.Context, client *github.Client, db *sql.DB, runUUID, org string, perPage int, repoIDByName map[string]int64) error {
	alerts, err := fetchPaginated(ctx, client, fmt.Sprintf("orgs/%s/code-scanning/alerts", org), perPage, func() interface{} {
		return &[]codeScanningAlert{}
	})
	if err != nil {
		return err
	}
	typed := alerts.([]codeScanningAlert)

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, a := range typed {
		repoID, ok := resolveRepoID(repoIDByName, a.Repository.FullName, a.Repository.Name)
		if !ok {
			continue
		}
		_, err := tx.Exec(`
			INSERT INTO code_scanning_alerts(
				run_uuid, repo_id, alert_number, state, rule_id, tool, severity,
				security_severity, created_at, fixed_at, most_recent_instance_json
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(run_uuid, repo_id, alert_number) DO UPDATE SET
				state = excluded.state,
				rule_id = excluded.rule_id,
				tool = excluded.tool,
				severity = excluded.severity,
				security_severity = excluded.security_severity,
				created_at = excluded.created_at,
				fixed_at = excluded.fixed_at,
				most_recent_instance_json = excluded.most_recent_instance_json
		`,
			runUUID,
			repoID,
			a.Number,
			a.State,
			a.Rule.ID,
			a.Tool.Name,
			a.Severity,
			a.SecuritySeverityLevel,
			formatTime(a.CreatedAt),
			formatTime(a.FixedAt),
			string(a.MostRecentInstance),
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func ingestSecretScanningAlerts(ctx context.Context, client *github.Client, db *sql.DB, runUUID, org string, perPage int, repoIDByName map[string]int64) error {
	alerts, err := fetchPaginated(ctx, client, fmt.Sprintf("orgs/%s/secret-scanning/alerts", org), perPage, func() interface{} {
		return &[]secretScanningAlert{}
	})
	if err != nil {
		return err
	}
	typed := alerts.([]secretScanningAlert)

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, a := range typed {
		repoID, ok := resolveRepoID(repoIDByName, a.Repository.FullName, a.Repository.Name)
		if !ok {
			continue
		}
		_, err := tx.Exec(`
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
		`,
			runUUID,
			repoID,
			a.Number,
			a.State,
			a.SecretType,
			a.Resolution,
			formatTime(a.CreatedAt),
			formatTime(a.UpdatedAt),
			formatTime(a.ResolvedAt),
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func fetchRepoRulesets(ctx context.Context, client *github.Client, owner, repo string, perPage int) ([]repoRuleset, error) {
	data, err := fetchPaginated(ctx, client, fmt.Sprintf("repos/%s/%s/rulesets", owner, repo), perPage, func() interface{} {
		return &[]json.RawMessage{}
	})
	if err != nil {
		return nil, err
	}
	rawItems := data.([]json.RawMessage)

	out := make([]repoRuleset, 0, len(rawItems))
	for _, raw := range rawItems {
		var rs repoRuleset
		if err := json.Unmarshal(raw, &rs); err != nil {
			return nil, err
		}
		rs.Raw = raw
		out = append(out, rs)
	}
	return out, nil
}

func ingestRepoRulesets(db *sql.DB, runUUID string, repoID int64, rulesets []repoRuleset) error {
	if len(rulesets) == 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, rs := range rulesets {
		_, err := tx.Exec(`
			INSERT INTO repo_rulesets(run_uuid, repo_id, ruleset_id, enforcement, target, raw_json)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(run_uuid, repo_id, ruleset_id) DO UPDATE SET
				enforcement = excluded.enforcement,
				target = excluded.target,
				raw_json = excluded.raw_json
		`, runUUID, repoID, rs.ID, rs.Enforcement, rs.Target, string(rs.Raw))
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func fetchWorkflowRuns(ctx context.Context, client *github.Client, owner, repo string, perPage int) ([]*github.WorkflowRun, error) {
	all := make([]*github.WorkflowRun, 0)
	page := 1
	for {
		opts := &github.ListWorkflowRunsOptions{ListOptions: github.ListOptions{PerPage: perPage, Page: page}}
		runs, resp, err := client.Actions.ListRepositoryWorkflowRuns(ctx, owner, repo, opts)
		if err != nil {
			return nil, err
		}
		all = append(all, runs.WorkflowRuns...)
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}
	return all, nil
}

func ingestWorkflowRuns(db *sql.DB, runUUID string, repoID int64, runs []*github.WorkflowRun) error {
	if len(runs) == 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, run := range runs {
		_, err := tx.Exec(`
			INSERT INTO workflow_runs(run_uuid, repo_id, run_id, workflow_name, status, conclusion, run_started_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(run_uuid, repo_id, run_id) DO UPDATE SET
				workflow_name = excluded.workflow_name,
				status = excluded.status,
				conclusion = excluded.conclusion,
				run_started_at = excluded.run_started_at,
				updated_at = excluded.updated_at
		`, runUUID, repoID, run.GetID(), run.GetName(), run.GetStatus(), run.GetConclusion(), formatGitHubTimePtr(run.RunStartedAt), formatGitHubTimePtr(run.UpdatedAt))
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func fetchPaginated(ctx context.Context, client *github.Client, endpoint string, perPage int, newSlicePtr func() interface{}) (interface{}, error) {
	page := 1
	accRaw := make([]json.RawMessage, 0)

	for {
		path := fmt.Sprintf("%s?per_page=%d&page=%d", endpoint, perPage, page)
		req, err := client.NewRequest("GET", path, nil)
		if err != nil {
			return nil, err
		}

		pageBuf := &[]json.RawMessage{}
		resp, err := client.Do(ctx, req, pageBuf)
		if err != nil {
			return nil, err
		}
		accRaw = append(accRaw, (*pageBuf)...)
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	result := newSlicePtr()
	bytes, err := json.Marshal(accRaw)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(bytes, result); err != nil {
		return nil, err
	}

	switch v := result.(type) {
	case *[]dependabotAlert:
		return *v, nil
	case *[]codeScanningAlert:
		return *v, nil
	case *[]secretScanningAlert:
		return *v, nil
	case *[]json.RawMessage:
		return *v, nil
	default:
		return nil, fmt.Errorf("unsupported pagination decode target")
	}
}

func exportCSVReport(db *sql.DB, runUUID, outputPath string) error {
	query := `
		SELECT
			r.full_name,
			(SELECT COUNT(1) FROM repo_dependencies rd WHERE rd.run_uuid = ? AND rd.repo_id = r.repo_id) AS dependency_count,
			(SELECT COUNT(1) FROM dependabot_alerts da WHERE da.run_uuid = ? AND da.repo_id = r.repo_id AND lower(da.state) = 'open') AS open_dependabot_alerts,
			(SELECT COUNT(1) FROM dependabot_alerts da WHERE da.run_uuid = ? AND da.repo_id = r.repo_id AND lower(da.state) = 'open' AND lower(da.severity) = 'critical') AS open_critical_dependabot_alerts,
			(SELECT COUNT(1) FROM code_scanning_alerts ca WHERE ca.run_uuid = ? AND ca.repo_id = r.repo_id AND lower(ca.state) = 'open') AS open_code_scanning_alerts,
			(SELECT COUNT(1) FROM secret_scanning_alerts sa WHERE sa.run_uuid = ? AND sa.repo_id = r.repo_id AND lower(sa.state) = 'open') AS open_secret_scanning_alerts,
			(SELECT COUNT(1) FROM workflow_runs wr WHERE wr.run_uuid = ? AND wr.repo_id = r.repo_id AND lower(COALESCE(wr.conclusion, '')) = 'failure') AS failed_workflow_runs
		FROM repos r
		WHERE r.run_uuid = ?
		ORDER BY open_critical_dependabot_alerts DESC, open_dependabot_alerts DESC, r.full_name ASC
	`

	rows, err := db.Query(query, runUUID, runUUID, runUUID, runUUID, runUUID, runUUID, runUUID)
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

func resolveRepoID(repoIDByName map[string]int64, fullName, name string) (int64, bool) {
	if fullName != "" {
		if id, ok := repoIDByName[fullName]; ok {
			return id, true
		}
	}
	if name != "" {
		if id, ok := repoIDByName[name]; ok {
			return id, true
		}
	}
	return 0, false
}

func extractPURL(pkg spdxPackage) string {
	for _, ref := range pkg.ExternalRefs {
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

func supplierToString(v interface{}) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return ""
		}
		return string(b)
	}
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
