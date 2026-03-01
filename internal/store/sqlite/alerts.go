package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"

	"github.com/AlvinRoe/orginv/internal/store/sqlite/sqlbatch"
	"github.com/google/go-github/v82/github"
)

func (s *Store) IngestDependabotAlerts(ctx context.Context, repoIDByName RepoIndex, alerts []*github.DependabotAlert) error {
	if err := s.IngestDependabotAlertsMain(ctx, repoIDByName, alerts); err != nil {
		return err
	}
	return s.IngestDependabotAlertsLinks(ctx, repoIDByName, alerts)
}

func (s *Store) IngestDependabotAlertsMain(ctx context.Context, repoIDByName RepoIndex, alerts []*github.DependabotAlert) error {
	batch := sqlbatch.New()

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

		if pkgName != "" {
			batch.Add("packages", buildPackageIdentityUpsertSQL(ecosystem, pkgName))
		}
		if stmt := buildAdvisoryUpsertSQL(securityAdv); stmt != "" {
			batch.Add("advisories", stmt)
		}
		for _, v := range securityAdv.Vulnerabilities {
			if v == nil {
				continue
			}
			pkg := v.GetPackage()
			if pkg.GetName() == "" {
				continue
			}
			batch.Add("packages", buildPackageIdentityUpsertSQL(pkg.GetEcosystem(), pkg.GetName()))
		}
		for _, ref := range securityAdv.References {
			if ref == nil || strings.TrimSpace(ref.GetURL()) == "" {
				continue
			}
			batch.Add("advisory_references", buildAdvisoryReferenceUpsertSQL(ref.GetURL()))
		}
		for _, cwe := range securityAdv.CWEs {
			if cwe == nil || strings.TrimSpace(cwe.GetCWEID()) == "" {
				continue
			}
			batch.Add("cwes", buildCWEUpsertSQL(cwe.GetCWEID(), cwe.GetName()))
		}
		batch.Add("dependabot_alerts", buildDependabotAlertUpsertSQL(repoID, ecosystem, pkgName, a, severity))
		inserted++
	}
	log.Printf("dependabot ingest summary: total=%d inserted=%d skipped_repo=%d", len(alerts), inserted, skippedRepo)
	return s.flushBatch(ctx, "dependabot main", batch)
}

func (s *Store) IngestDependabotAlertsLinks(ctx context.Context, repoIDByName RepoIndex, alerts []*github.DependabotAlert) error {
	batch := sqlbatch.New()
	rebuiltAdvisories := make(map[string]struct{})
	for _, a := range alerts {
		if a == nil {
			continue
		}
		repoID, ok := resolveAlertRepoID(repoIDByName, a.GetRepository())
		if !ok {
			continue
		}
		adv := a.GetSecurityAdvisory()
		if adv == nil || (strings.TrimSpace(adv.GetGHSAID()) == "" && strings.TrimSpace(adv.GetCVEID()) == "") {
			continue
		}
		advisoryIDExpr := advisoryIDSubquery(adv.GetGHSAID(), adv.GetCVEID())
		batch.Add("dependabot_alert_advisories", fmt.Sprintf(
			`INSERT INTO dependabot_alert_advisories(repo_id, alert_number, advisory_id)
			VALUES (%d, %d, %s)
			ON CONFLICT(repo_id, alert_number) DO UPDATE SET advisory_id = excluded.advisory_id`,
			repoID, a.GetNumber(), advisoryIDExpr,
		))
		advisoryKey := strings.TrimSpace(adv.GetGHSAID()) + "|" + strings.TrimSpace(adv.GetCVEID())
		if _, done := rebuiltAdvisories[advisoryKey]; done {
			continue
		}
		batch.Add("advisory_vulnerabilities", fmt.Sprintf(`DELETE FROM advisory_vulnerabilities WHERE advisory_id = %s`, advisoryIDExpr))
		batch.Add("advisory_reference_links", fmt.Sprintf(`DELETE FROM advisory_reference_links WHERE advisory_id = %s`, advisoryIDExpr))
		batch.Add("advisory_cwes", fmt.Sprintf(`DELETE FROM advisory_cwes WHERE advisory_id = %s`, advisoryIDExpr))

		packageOrdinals := make(map[string]int)
		for _, v := range adv.Vulnerabilities {
			if v == nil {
				continue
			}
			pkg := v.GetPackage()
			if pkg.GetName() == "" {
				continue
			}
			pkgKey := defaultEcosystem(pkg.GetEcosystem()) + ":" + strings.TrimSpace(pkg.GetName())
			packageOrdinals[pkgKey]++
			batch.Add("advisory_vulnerabilities", buildAdvisoryVulnerabilityInsertSQL(advisoryIDExpr, packageIDSubquery(pkg.GetEcosystem(), pkg.GetName()), packageOrdinals[pkgKey], v))
		}
		for i, ref := range adv.References {
			if ref == nil || strings.TrimSpace(ref.GetURL()) == "" {
				continue
			}
			batch.Add("advisory_reference_links", buildAdvisoryReferenceLinkInsertSQL(advisoryIDExpr, ref.GetURL(), i+1))
		}
		for _, cwe := range adv.CWEs {
			if cwe == nil || strings.TrimSpace(cwe.GetCWEID()) == "" {
				continue
			}
			batch.Add("advisory_cwes", buildAdvisoryCWEInsertSQL(advisoryIDExpr, cwe.GetCWEID()))
		}
		rebuiltAdvisories[advisoryKey] = struct{}{}
	}
	return s.flushBatch(ctx, "dependabot links", batch)
}

func (s *Store) IngestCodeScanningAlerts(ctx context.Context, repoIDByName RepoIndex, alerts []*github.Alert) error {
	batch := sqlbatch.New()

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
		snapshot := snapshotCodeScanningInstance(a.GetMostRecentInstance())
		batch.Add("code_scanning_alerts", buildCodeScanningAlertUpsertSQL(repoID, a, snapshot))
		inserted++
	}
	log.Printf("code scanning ingest summary: total=%d inserted=%d skipped_repo=%d", len(alerts), inserted, skippedRepo)
	return s.flushBatch(ctx, "code scanning", batch)
}

func (s *Store) IngestSecretScanningAlerts(ctx context.Context, repoIDByName RepoIndex, alerts []*github.SecretScanningAlert) error {
	batch := sqlbatch.New()

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
		loc := a.GetFirstLocationDetected()
		var (
			path                  string
			startLine             interface{}
			endLine               interface{}
			startColumn           interface{}
			endColumn             interface{}
			blobSHA               string
			blobURL               string
			commitSHA             string
			commitURL             string
			pullRequestCommentURL string
		)
		if loc != nil {
			path = loc.GetPath()
			startLine = nullableIntPtr(loc.Startline)
			endLine = nullableIntPtr(loc.EndLine)
			startColumn = nullableIntPtr(loc.StartColumn)
			endColumn = nullableIntPtr(loc.EndColumn)
			blobSHA = loc.GetBlobSHA()
			blobURL = loc.GetBlobURL()
			commitSHA = loc.GetCommitSHA()
			commitURL = loc.GetCommitURL()
			pullRequestCommentURL = loc.GetPullRequestCommentURL()
		}
		batch.Add("secret_alerts", buildSecretAlertUpsertSQL(repoID, a, path, startLine, endLine, startColumn, endColumn, blobSHA, blobURL, commitSHA, commitURL, pullRequestCommentURL))
		inserted++
	}
	log.Printf("secret scanning ingest summary: total=%d inserted=%d skipped_repo=%d", len(alerts), inserted, skippedRepo)
	return s.flushBatch(ctx, "secret scanning", batch)
}

func buildPackageIdentityUpsertSQL(ecosystem, name string) string {
	if strings.TrimSpace(name) == "" {
		return ""
	}
	return fmt.Sprintf(
		`INSERT INTO packages(ecosystem, name)
		VALUES (%s, %s)
		ON CONFLICT(ecosystem, name) DO NOTHING`,
		sqlString(defaultEcosystem(ecosystem)),
		sqlString(strings.TrimSpace(name)),
	)
}

func buildDependabotAlertUpsertSQL(repoID int64, ecosystem, pkgName string, a *github.DependabotAlert, severity string) string {
	packageExpr := "NULL"
	if strings.TrimSpace(pkgName) != "" {
		packageExpr = packageIDSubquery(ecosystem, pkgName)
	}
	return fmt.Sprintf(
		`INSERT INTO dependabot_alerts(
			repo_id, alert_number, state, severity, package_id, manifest_path, created_at,
			updated_at, fixed_at, dismissed_reason, url, html_url, dismissed_at, dismissed_comment,
			auto_dismissed_at, dependency_scope
		) VALUES (
			%d, %d, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
		)
		ON CONFLICT(repo_id, alert_number) DO UPDATE SET
			state = excluded.state,
			severity = excluded.severity,
			package_id = excluded.package_id,
			manifest_path = excluded.manifest_path,
			created_at = excluded.created_at,
			updated_at = excluded.updated_at,
			fixed_at = excluded.fixed_at,
			dismissed_reason = excluded.dismissed_reason,
			url = excluded.url,
			html_url = excluded.html_url,
			dismissed_at = excluded.dismissed_at,
			dismissed_comment = excluded.dismissed_comment,
			auto_dismissed_at = excluded.auto_dismissed_at,
			dependency_scope = excluded.dependency_scope`,
		repoID,
		a.GetNumber(),
		sqlString(a.GetState()),
		sqlString(severity),
		packageExpr,
		sqlString(a.GetDependency().GetManifestPath()),
		sqlString(formatGitHubTimePtr(a.CreatedAt)),
		sqlString(formatGitHubTimePtr(a.UpdatedAt)),
		sqlString(formatGitHubTimePtr(a.FixedAt)),
		sqlString(a.GetDismissedReason()),
		sqlString(a.GetURL()),
		sqlString(a.GetHTMLURL()),
		sqlString(formatGitHubTimePtr(a.DismissedAt)),
		sqlString(a.GetDismissedComment()),
		sqlString(formatGitHubTimePtr(a.AutoDismissedAt)),
		sqlString(a.GetDependency().GetScope()),
	)
}

func buildAdvisoryUpsertSQL(adv *github.DependabotSecurityAdvisory) string {
	if adv == nil {
		return ""
	}
	ghsaID := strings.TrimSpace(adv.GetGHSAID())
	cveID := strings.TrimSpace(adv.GetCVEID())
	if ghsaID == "" && cveID == "" {
		return ""
	}

	cvssScore := interface{}(nil)
	cvssVector := ""
	epssPercentage := interface{}(nil)
	epssPercentile := interface{}(nil)
	severity := adv.GetSeverity()
	if adv.CVSS != nil {
		cvssScore = normalizeCVSSScore(adv.CVSS.Score, severity)
		cvssVector = adv.CVSS.GetVectorString()
	}
	epssPercentage = epssPercentageValue(adv.EPSS)
	epssPercentile = epssPercentileValue(adv.EPSS)

	return fmt.Sprintf(
		`INSERT INTO advisories(
			ghsa_id, cve_id, summary, description, severity, cvss_score, cvss_vector_string,
			epss_percentage, epss_percentile, published_at, updated_at, withdrawn_at
		) VALUES (
			%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
		)
		ON CONFLICT(ghsa_id, cve_id) DO UPDATE SET
			summary = excluded.summary,
			description = excluded.description,
			severity = excluded.severity,
			cvss_score = excluded.cvss_score,
			cvss_vector_string = excluded.cvss_vector_string,
			epss_percentage = excluded.epss_percentage,
			epss_percentile = excluded.epss_percentile,
			published_at = excluded.published_at,
			updated_at = excluded.updated_at,
			withdrawn_at = excluded.withdrawn_at`,
		sqlString(ghsaID),
		sqlString(cveID),
		sqlString(adv.GetSummary()),
		sqlString(adv.GetDescription()),
		sqlString(severity),
		sqlValue(cvssScore),
		sqlString(cvssVector),
		sqlValue(epssPercentage),
		sqlValue(epssPercentile),
		sqlString(formatGitHubTimePtr(adv.PublishedAt)),
		sqlString(formatGitHubTimePtr(adv.UpdatedAt)),
		sqlString(formatGitHubTimePtr(adv.WithdrawnAt)),
	)
}

func buildAdvisoryReferenceUpsertSQL(url string) string {
	return fmt.Sprintf(
		`INSERT INTO advisory_references(url)
		VALUES (%s)
		ON CONFLICT(url) DO NOTHING`,
		sqlString(strings.TrimSpace(url)),
	)
}

func buildCWEUpsertSQL(cweID, name string) string {
	return fmt.Sprintf(
		`INSERT INTO cwes(cwe_id, name)
		VALUES (%s, %s)
		ON CONFLICT(cwe_id) DO UPDATE SET name = excluded.name`,
		sqlString(strings.TrimSpace(cweID)),
		sqlString(name),
	)
}

func buildAdvisoryVulnerabilityInsertSQL(advisoryIDExpr, packageIDExpr string, ordinal int, v *github.AdvisoryVulnerability) string {
	return fmt.Sprintf(
		`INSERT INTO advisory_vulnerabilities(
			advisory_id, package_id, package_ordinal, severity, vulnerable_version_range, first_patched_version
		) VALUES (%s, %s, %d, %s, %s, %s)`,
		advisoryIDExpr,
		packageIDExpr,
		ordinal,
		sqlString(v.GetSeverity()),
		sqlString(v.GetVulnerableVersionRange()),
		sqlString(v.GetFirstPatchedVersion().GetIdentifier()),
	)
}

func buildAdvisoryReferenceLinkInsertSQL(advisoryIDExpr, url string, refNum int) string {
	return fmt.Sprintf(
		`INSERT INTO advisory_reference_links(advisory_id, reference_id, ref_num)
		VALUES (
			%s,
			(SELECT reference_id FROM advisory_references WHERE url = %s LIMIT 1),
			%d
		)
		ON CONFLICT(advisory_id, reference_id) DO NOTHING`,
		advisoryIDExpr,
		sqlString(strings.TrimSpace(url)),
		refNum,
	)
}

func buildAdvisoryCWEInsertSQL(advisoryIDExpr, cweID string) string {
	return fmt.Sprintf(
		`INSERT INTO advisory_cwes(advisory_id, cwe_id)
		VALUES (%s, %s)
		ON CONFLICT(advisory_id, cwe_id) DO NOTHING`,
		advisoryIDExpr,
		sqlString(strings.TrimSpace(cweID)),
	)
}

func buildCodeScanningAlertUpsertSQL(repoID int64, a *github.Alert, snapshot codeScanningInstanceSnapshot) string {
	return fmt.Sprintf(
		`INSERT INTO code_scanning_alerts(
			repo_id, alert_number, state, severity,
			created_at, fixed_at, updated_at, closed_at, url, html_url, instances_url, dismissed_at, dismissed_reason, dismissed_comment,
			ref, commit_sha, path, start_line, end_line, start_column, end_column, most_recent_state, category, classifications, analysis_key
		) VALUES (
			%d, %d, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
		)
		ON CONFLICT(repo_id, alert_number) DO UPDATE SET
			state = excluded.state,
			severity = excluded.severity,
			created_at = excluded.created_at,
			fixed_at = excluded.fixed_at,
			updated_at = excluded.updated_at,
			closed_at = excluded.closed_at,
			url = excluded.url,
			html_url = excluded.html_url,
			instances_url = excluded.instances_url,
			dismissed_at = excluded.dismissed_at,
			dismissed_reason = excluded.dismissed_reason,
			dismissed_comment = excluded.dismissed_comment,
			ref = excluded.ref,
			commit_sha = excluded.commit_sha,
			path = excluded.path,
			start_line = excluded.start_line,
			end_line = excluded.end_line,
			start_column = excluded.start_column,
			end_column = excluded.end_column,
			most_recent_state = excluded.most_recent_state,
			category = excluded.category,
			classifications = excluded.classifications,
			analysis_key = excluded.analysis_key`,
		repoID,
		a.GetNumber(),
		sqlString(a.GetState()),
		sqlString(a.GetRuleSeverity()),
		sqlString(formatGitHubTimePtr(a.CreatedAt)),
		sqlString(formatGitHubTimePtr(a.FixedAt)),
		sqlString(formatGitHubTimePtr(a.UpdatedAt)),
		sqlString(formatGitHubTimePtr(a.ClosedAt)),
		sqlString(a.GetURL()),
		sqlString(a.GetHTMLURL()),
		sqlString(a.GetInstancesURL()),
		sqlString(formatGitHubTimePtr(a.DismissedAt)),
		sqlString(a.GetDismissedReason()),
		sqlString(a.GetDismissedComment()),
		sqlString(snapshot.ref),
		sqlString(snapshot.commitSHA),
		sqlString(snapshot.path),
		sqlValue(snapshot.startLine),
		sqlValue(snapshot.endLine),
		sqlValue(snapshot.startColumn),
		sqlValue(snapshot.endColumn),
		sqlString(snapshot.state),
		sqlString(snapshot.category),
		sqlString(snapshot.classifications),
		sqlString(mostRecentAnalysisKey(a.GetMostRecentInstance())),
	)
}

func buildSecretAlertUpsertSQL(repoID int64, a *github.SecretScanningAlert, path string, startLine, endLine, startColumn, endColumn interface{}, blobSHA, blobURL, commitSHA, commitURL, pullRequestCommentURL string) string {
	return fmt.Sprintf(
		`INSERT INTO secret_alerts(
			repo_id, alert_number, state, secret_type, resolution, created_at, updated_at, resolved_at,
			url, html_url, locations_url, secret_type_display_name, secret, is_base64_encoded, multi_repo, publicly_leaked,
			push_protection_bypassed,
			push_protection_bypassed_at, resolution_comment, push_protection_bypass_request_comment,
			push_protection_bypass_request_html_url, validity, has_more_locations,
			path, start_line, end_line, start_column, end_column, blob_sha, blob_url, commit_sha, commit_url, pull_request_comment_url
		) VALUES (
			%d, %d, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
		)
		ON CONFLICT(repo_id, alert_number) DO UPDATE SET
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
			push_protection_bypassed_at = excluded.push_protection_bypassed_at,
			resolution_comment = excluded.resolution_comment,
			push_protection_bypass_request_comment = excluded.push_protection_bypass_request_comment,
			push_protection_bypass_request_html_url = excluded.push_protection_bypass_request_html_url,
			validity = excluded.validity,
			has_more_locations = excluded.has_more_locations,
			path = excluded.path,
			start_line = excluded.start_line,
			end_line = excluded.end_line,
			start_column = excluded.start_column,
			end_column = excluded.end_column,
			blob_sha = excluded.blob_sha,
			blob_url = excluded.blob_url,
			commit_sha = excluded.commit_sha,
			commit_url = excluded.commit_url,
			pull_request_comment_url = excluded.pull_request_comment_url`,
		repoID,
		a.GetNumber(),
		sqlString(a.GetState()),
		sqlString(a.GetSecretType()),
		sqlString(a.GetResolution()),
		sqlString(formatGitHubTimePtr(a.CreatedAt)),
		sqlString(formatGitHubTimePtr(a.UpdatedAt)),
		sqlString(formatGitHubTimePtr(a.ResolvedAt)),
		sqlString(a.GetURL()),
		sqlString(a.GetHTMLURL()),
		sqlString(a.GetLocationsURL()),
		sqlString(a.GetSecretTypeDisplayName()),
		sqlString(a.GetSecret()),
		sqlValue(boolPtrToIntPtr(a.IsBase64Encoded)),
		sqlValue(boolPtrToIntPtr(a.MultiRepo)),
		sqlValue(boolPtrToIntPtr(a.PubliclyLeaked)),
		sqlValue(boolPtrToIntPtr(a.PushProtectionBypassed)),
		sqlString(formatGitHubTimePtr(a.PushProtectionBypassedAt)),
		sqlString(a.GetResolutionComment()),
		sqlString(a.GetPushProtectionBypassRequestComment()),
		sqlString(a.GetPushProtectionBypassRequestHTMLURL()),
		sqlString(a.GetValidity()),
		sqlValue(boolPtrToIntPtr(a.HasMoreLocations)),
		sqlString(path),
		sqlValue(startLine),
		sqlValue(endLine),
		sqlValue(startColumn),
		sqlValue(endColumn),
		sqlString(blobSHA),
		sqlString(blobURL),
		sqlString(commitSHA),
		sqlString(commitURL),
		sqlString(pullRequestCommentURL),
	)
}

func upsertDependabotAdvisoryMainTx(tx *sql.Tx, a *github.DependabotAlert) error {
	if a == nil {
		return nil
	}
	adv := a.GetSecurityAdvisory()
	advisoryID, err := upsertSecurityAdvisoryTx(tx, adv)
	if err != nil {
		return err
	}
	if adv == nil || advisoryID == 0 {
		return nil
	}

	// Ensure base rows for link-stage FK targets exist.
	for _, v := range adv.Vulnerabilities {
		if v == nil {
			continue
		}
		pkg := v.GetPackage()
		if _, err := upsertPackageIdentityTx(tx, pkg.GetEcosystem(), pkg.GetName()); err != nil {
			return err
		}
	}

	for _, ref := range adv.References {
		if ref == nil {
			continue
		}
		if _, err := upsertAdvisoryReferenceTx(tx, ref.GetURL()); err != nil {
			return err
		}
	}

	for _, cwe := range adv.CWEs {
		if cwe == nil {
			continue
		}
		cweID := strings.TrimSpace(cwe.GetCWEID())
		if cweID == "" {
			continue
		}
		if err := upsertCWETx(tx, cweID, cwe.GetName()); err != nil {
			return err
		}
	}

	return nil
}

func rebuildDependabotAdvisoryLinksTx(tx *sql.Tx, advisoryID int64, adv *github.DependabotSecurityAdvisory) error {
	if adv == nil || advisoryID == 0 {
		return nil
	}

	if _, err := tx.Exec(`
		DELETE FROM advisory_vulnerabilities WHERE advisory_id = ?;
		DELETE FROM advisory_reference_links WHERE advisory_id = ?;
		DELETE FROM advisory_cwes WHERE advisory_id = ?;
	`, advisoryID, advisoryID, advisoryID); err != nil {
		return err
	}

	vulnStmt, err := tx.Prepare(`
		INSERT INTO advisory_vulnerabilities(
			advisory_id, package_id, package_ordinal, severity, vulnerable_version_range,
			first_patched_version
		) VALUES (?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer vulnStmt.Close()

	advRefStmt, err := tx.Prepare(`
		INSERT INTO advisory_reference_links(advisory_id, reference_id, ref_num)
		VALUES (?, ?, ?)
		ON CONFLICT(advisory_id, reference_id) DO NOTHING
	`)
	if err != nil {
		return err
	}
	defer advRefStmt.Close()

	advCWEStmt, err := tx.Prepare(`
		INSERT INTO advisory_cwes(advisory_id, cwe_id)
		VALUES (?, ?)
		ON CONFLICT(advisory_id, cwe_id) DO NOTHING
	`)
	if err != nil {
		return err
	}
	defer advCWEStmt.Close()

	packageOrdinals := make(map[int64]int)
	for _, v := range adv.Vulnerabilities {
		if v == nil {
			continue
		}
		pkg := v.GetPackage()
		packageID, err := lookupPackageIdentityIDTx(tx, pkg.GetEcosystem(), pkg.GetName())
		if err != nil {
			return err
		}
		if packageID == 0 {
			return fmt.Errorf("advisory package not found for ecosystem=%q name=%q advisory_id=%d", pkg.GetEcosystem(), pkg.GetName(), advisoryID)
		}
		packageOrdinals[packageID]++
		packageOrdinal := packageOrdinals[packageID]
		_, err = vulnStmt.Exec(advisoryID, packageID, packageOrdinal, v.GetSeverity(),
			v.GetVulnerableVersionRange(), v.GetFirstPatchedVersion().GetIdentifier())
		if err != nil {
			return err
		}
	}

	for i, ref := range adv.References {
		if ref == nil {
			continue
		}
		referenceID, err := lookupAdvisoryReferenceIDTx(tx, ref.GetURL())
		if err != nil {
			return err
		}
		if referenceID == 0 {
			return fmt.Errorf("advisory reference not found for advisory_id=%d url=%q", advisoryID, ref.GetURL())
		}
		_, err = advRefStmt.Exec(advisoryID, referenceID, i+1)
		if err != nil {
			return err
		}
	}

	for _, cwe := range adv.CWEs {
		if cwe == nil {
			continue
		}
		cweID := strings.TrimSpace(cwe.GetCWEID())
		if cweID == "" {
			continue
		}
		_, err := advCWEStmt.Exec(advisoryID, cweID)
		if err != nil {
			return err
		}
	}

	return nil
}

func findSecurityAdvisoryIDTx(tx *sql.Tx, adv *github.DependabotSecurityAdvisory) (int64, error) {
	if adv == nil {
		return 0, nil
	}
	ghsaID := strings.TrimSpace(adv.GetGHSAID())
	cveID := strings.TrimSpace(adv.GetCVEID())
	if ghsaID == "" && cveID == "" {
		return 0, nil
	}
	var advisoryID int64
	err := tx.QueryRow(`
		SELECT advisory_id
		FROM advisories
		WHERE ghsa_id = ? AND cve_id = ?
		LIMIT 1
	`, ghsaID, cveID).Scan(&advisoryID)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return advisoryID, nil
}

func upsertSecurityAdvisoryTx(tx *sql.Tx, adv *github.DependabotSecurityAdvisory) (int64, error) {
	ghsaID := ""
	cveID := ""
	if adv != nil {
		ghsaID = strings.TrimSpace(adv.GetGHSAID())
		cveID = strings.TrimSpace(adv.GetCVEID())
	}
	if ghsaID == "" && cveID == "" {
		return 0, nil
	}

	var existingID int64
	err := tx.QueryRow(`
		SELECT advisory_id
		FROM advisories
		WHERE ghsa_id = ? AND cve_id = ?
		LIMIT 1
	`, ghsaID, cveID).Scan(&existingID)
	if err != nil && err != sql.ErrNoRows {
		return 0, err
	}

	cvssScore := interface{}(nil)
	cvssVector := ""
	epssPercentage := interface{}(nil)
	epssPercentile := interface{}(nil)
	publishedAt := ""
	updatedAt := ""
	withdrawnAt := ""
	summary := ""
	description := ""
	severity := ""
	if adv != nil {
		severity = adv.GetSeverity()
		if adv.CVSS != nil {
			cvssScore = normalizeCVSSScore(adv.CVSS.Score, severity)
			cvssVector = adv.CVSS.GetVectorString()
		}
		epssPercentage = epssPercentageValue(adv.EPSS)
		epssPercentile = epssPercentileValue(adv.EPSS)
		publishedAt = formatGitHubTimePtr(adv.PublishedAt)
		updatedAt = formatGitHubTimePtr(adv.UpdatedAt)
		withdrawnAt = formatGitHubTimePtr(adv.WithdrawnAt)
		summary = adv.GetSummary()
		description = adv.GetDescription()
	}

	if existingID != 0 {
		_, err = tx.Exec(`
			UPDATE advisories
			SET
				summary = ?,
				description = ?,
				severity = ?,
				cvss_score = ?,
				cvss_vector_string = ?,
				epss_percentage = ?,
				epss_percentile = ?,
				published_at = ?,
				updated_at = ?,
				withdrawn_at = ?
			WHERE advisory_id = ?
		`, summary, description, severity, cvssScore, cvssVector, epssPercentage, epssPercentile, publishedAt, updatedAt, withdrawnAt, existingID)
		return existingID, err
	}

	res, err := tx.Exec(`
		INSERT INTO advisories(
			ghsa_id, cve_id, summary, description, severity, cvss_score,
			cvss_vector_string, epss_percentage, epss_percentile, published_at, updated_at, withdrawn_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, ghsaID, cveID, summary, description, severity, cvssScore, cvssVector, epssPercentage, epssPercentile, publishedAt, updatedAt, withdrawnAt)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func normalizeCVSSScore(score *float64, severity string) interface{} {
	if score == nil {
		return nil
	}
	// GitHub advisories can carry severity while score is effectively missing (0.0).
	// Preserve 0.0 only when severity is explicitly "none".
	if *score == 0 && !strings.EqualFold(strings.TrimSpace(severity), "none") {
		return nil
	}
	return *score
}

func upsertAdvisoryReferenceTx(tx *sql.Tx, url string) (int64, error) {
	url = strings.TrimSpace(url)
	if url == "" {
		return 0, fmt.Errorf("dependabot advisory reference url is empty")
	}
	res, err := tx.Exec(`
		INSERT INTO advisory_references(url)
		VALUES (?)
		ON CONFLICT(url) DO NOTHING
	`, url)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if id != 0 {
		return id, nil
	}
	if err := tx.QueryRow(`SELECT reference_id FROM advisory_references WHERE url = ?`, url).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

func lookupAdvisoryReferenceIDTx(tx *sql.Tx, url string) (int64, error) {
	url = strings.TrimSpace(url)
	if url == "" {
		return 0, nil
	}
	var id int64
	err := tx.QueryRow(`SELECT reference_id FROM advisory_references WHERE url = ? LIMIT 1`, url).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return id, nil
}

func upsertCWETx(tx *sql.Tx, cweID, name string) error {
	_, err := tx.Exec(`
		INSERT INTO cwes(cwe_id, name)
		VALUES (?, ?)
		ON CONFLICT(cwe_id) DO UPDATE SET name = excluded.name
	`, cweID, name)
	return err
}
