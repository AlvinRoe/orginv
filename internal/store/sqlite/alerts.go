package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"

	"github.com/google/go-github/v82/github"
)

func (s *Store) IngestDependabotAlerts(ctx context.Context, repoIDByName RepoIndex, alerts []*github.DependabotAlert) error {
	if err := s.IngestDependabotAlertsMain(ctx, repoIDByName, alerts); err != nil {
		return err
	}
	return s.IngestDependabotAlertsLinks(ctx, repoIDByName, alerts)
}

func (s *Store) IngestDependabotAlertsMain(ctx context.Context, repoIDByName RepoIndex, alerts []*github.DependabotAlert) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO dependabot_alerts(
			repo_id, alert_number, state, severity, package_key_id, manifest_path, created_at,
			updated_at, fixed_at, dismissed_reason, url, html_url, dismissed_at, dismissed_comment,
			auto_dismissed_at, dependency_scope
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(repo_id, alert_number) DO UPDATE SET
			state = excluded.state,
			severity = excluded.severity,
			package_key_id = excluded.package_key_id,
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
			dependency_scope = excluded.dependency_scope
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

		packageKeyID, depErr := upsertPackageKeyTx(tx, ecosystem, pkgName)
		if depErr != nil {
			return depErr
		}

		_, err = stmt.ExecContext(
			ctx,
			repoID,
			a.GetNumber(),
			a.GetState(),
			severity,
			nullableInt64Value(packageKeyID),
			dependency.GetManifestPath(),
			formatGitHubTimePtr(a.CreatedAt),
			formatGitHubTimePtr(a.UpdatedAt),
			formatGitHubTimePtr(a.FixedAt),
			a.GetDismissedReason(),
			a.GetURL(),
			a.GetHTMLURL(),
			formatGitHubTimePtr(a.DismissedAt),
			a.GetDismissedComment(),
			formatGitHubTimePtr(a.AutoDismissedAt),
			dependency.GetScope(),
		)
		if err != nil {
			return err
		}
		if err := upsertDependabotAdvisoryMainTx(tx, a); err != nil {
			return err
		}
		inserted++
	}
	log.Printf("dependabot ingest summary: total=%d inserted=%d skipped_repo=%d", len(alerts), inserted, skippedRepo)

	return tx.Commit()
}

func (s *Store) IngestDependabotAlertsLinks(ctx context.Context, repoIDByName RepoIndex, alerts []*github.DependabotAlert) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	linkStmt, err := tx.Prepare(`
		INSERT INTO dependabot_alert_advisories(repo_id, alert_number, advisory_id)
		VALUES (?, ?, ?)
		ON CONFLICT(repo_id, alert_number) DO UPDATE SET advisory_id = excluded.advisory_id
	`)
	if err != nil {
		return err
	}
	defer linkStmt.Close()

	rebuiltAdvisories := make(map[int64]struct{})
	for _, a := range alerts {
		if a == nil {
			continue
		}
		repoID, ok := resolveAlertRepoID(repoIDByName, a.GetRepository())
		if !ok {
			continue
		}
		advisoryID, err := findSecurityAdvisoryIDTx(tx, a.GetSecurityAdvisory())
		if err != nil {
			return err
		}
		if advisoryID == 0 {
			continue
		}
		if _, err := linkStmt.Exec(repoID, a.GetNumber(), advisoryID); err != nil {
			return err
		}
		if _, done := rebuiltAdvisories[advisoryID]; done {
			continue
		}
		if err := rebuildDependabotAdvisoryLinksTx(tx, advisoryID, a.GetSecurityAdvisory()); err != nil {
			return err
		}
		rebuiltAdvisories[advisoryID] = struct{}{}
	}

	return tx.Commit()
}

func (s *Store) IngestCodeScanningAlerts(ctx context.Context, repoIDByName RepoIndex, alerts []*github.Alert) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO code_scanning_alerts(
			repo_id, alert_number, state, severity,
			created_at, fixed_at, updated_at, closed_at, url, html_url, instances_url, dismissed_at, dismissed_reason, dismissed_comment,
			ref, commit_sha, path, start_line, end_line, start_column, end_column, most_recent_state, category, classifications, analysis_key
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
			analysis_key = excluded.analysis_key
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
		snapshot := snapshotCodeScanningInstance(a.GetMostRecentInstance())
		_, err = stmt.ExecContext(
			ctx,
			repoID,
			a.GetNumber(),
			a.GetState(),
			a.GetRuleSeverity(),
			formatGitHubTimePtr(a.CreatedAt),
			formatGitHubTimePtr(a.FixedAt),
			formatGitHubTimePtr(a.UpdatedAt),
			formatGitHubTimePtr(a.ClosedAt),
			a.GetURL(),
			a.GetHTMLURL(),
			a.GetInstancesURL(),
			formatGitHubTimePtr(a.DismissedAt),
			a.GetDismissedReason(),
			a.GetDismissedComment(),
			snapshot.ref,
			snapshot.commitSHA,
			snapshot.path,
			snapshot.startLine,
			snapshot.endLine,
			snapshot.startColumn,
			snapshot.endColumn,
			snapshot.state,
			snapshot.category,
			snapshot.classifications,
			mostRecentAnalysisKey(a.GetMostRecentInstance()),
		)
		if err != nil {
			return err
		}
		inserted++
	}
	log.Printf("code scanning ingest summary: total=%d inserted=%d skipped_repo=%d", len(alerts), inserted, skippedRepo)

	return tx.Commit()
}

func (s *Store) IngestSecretScanningAlerts(ctx context.Context, repoIDByName RepoIndex, alerts []*github.SecretScanningAlert) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO secret_alerts(
			repo_id, alert_number, state, secret_type, resolution, created_at, updated_at, resolved_at,
			url, html_url, locations_url, secret_type_display_name, secret, is_base64_encoded, multi_repo, publicly_leaked,
			push_protection_bypassed,
			push_protection_bypassed_at, resolution_comment, push_protection_bypass_request_comment,
			push_protection_bypass_request_html_url, validity, has_more_locations,
			path, start_line, end_line, start_column, end_column, blob_sha, blob_url, commit_sha, commit_url, pull_request_comment_url
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
			pull_request_comment_url = excluded.pull_request_comment_url
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
		_, err := stmt.ExecContext(
			ctx,
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
			formatGitHubTimePtr(a.PushProtectionBypassedAt),
			a.GetResolutionComment(),
			a.GetPushProtectionBypassRequestComment(),
			a.GetPushProtectionBypassRequestHTMLURL(),
			a.GetValidity(),
			boolPtrToIntPtr(a.HasMoreLocations),
			path,
			startLine,
			endLine,
			startColumn,
			endColumn,
			blobSHA,
			blobURL,
			commitSHA,
			commitURL,
			pullRequestCommentURL,
		)
		if err != nil {
			return err
		}
		inserted++
	}
	log.Printf("secret scanning ingest summary: total=%d inserted=%d skipped_repo=%d", len(alerts), inserted, skippedRepo)

	return tx.Commit()
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
		if _, err := upsertPackageKeyTx(tx, pkg.GetEcosystem(), pkg.GetName()); err != nil {
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
			advisory_id, package_key_id, package_ordinal, severity, vulnerable_version_range,
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
		packageKeyID, err := lookupPackageKeyIDTx(tx, pkg.GetEcosystem(), pkg.GetName())
		if err != nil {
			return err
		}
		if packageKeyID == 0 {
			return fmt.Errorf("advisory package key not found for ecosystem=%q name=%q advisory_id=%d", pkg.GetEcosystem(), pkg.GetName(), advisoryID)
		}
		packageOrdinals[packageKeyID]++
		packageOrdinal := packageOrdinals[packageKeyID]
		_, err = vulnStmt.Exec(advisoryID, packageKeyID, packageOrdinal, v.GetSeverity(),
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
