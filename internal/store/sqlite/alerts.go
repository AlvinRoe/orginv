package sqlite

import (
	"database/sql"
	"fmt"
	"log"
	"strings"

	"github.com/google/go-github/v82/github"
)

func ingestDependabotAlerts(db *sql.DB, repoIDByName map[string]int64, alerts []*github.DependabotAlert) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO dependabot_alerts(
			repo_id, alert_number, state, severity, package_id, manifest_path, created_at,
			updated_at, fixed_at, dismissed_reason, url, html_url, dismissed_at, dismissed_comment,
			auto_dismissed_at, dependency_scope
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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

		packageID, depErr := upsertPackageTx(tx, ecosystem, pkgName, "", "", "", "", "", "", nil)
		if depErr != nil {
			return depErr
		}

		_, err = stmt.Exec(
			repoID,
			a.GetNumber(),
			a.GetState(),
			severity,
			nullableInt64Value(packageID),
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
		if err := upsertDependabotAdvisoryTx(tx, repoID, a); err != nil {
			return err
		}
		inserted++
	}
	log.Printf("dependabot ingest summary: total=%d inserted=%d skipped_repo=%d", len(alerts), inserted, skippedRepo)

	return tx.Commit()
}

func ingestCodeScanningAlerts(db *sql.DB, repoIDByName map[string]int64, alerts []*github.Alert) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO code_scanning_alerts(
			repo_id, alert_number, state, severity,
			created_at, fixed_at, updated_at, closed_at, url, html_url, instances_url, dismissed_at, dismissed_reason, dismissed_comment
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
			dismissed_comment = excluded.dismissed_comment
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
		_, err = stmt.Exec(
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
		)
		if err != nil {
			return err
		}
		if err := upsertCodeScanningAlertInstanceTx(tx, repoID, a.GetNumber(), a.GetMostRecentInstance()); err != nil {
			return err
		}
		inserted++
	}
	log.Printf("code scanning ingest summary: total=%d inserted=%d skipped_repo=%d", len(alerts), inserted, skippedRepo)

	return tx.Commit()
}

func upsertCodeScanningAlertInstanceTx(tx *sql.Tx, repoID int64, alertNumber int, inst *github.MostRecentInstance) error {
	if _, err := tx.Exec(`DELETE FROM code_scanning_alert_instances WHERE repo_id = ? AND alert_number = ?`, repoID, alertNumber); err != nil {
		return err
	}
	snapshot := snapshotCodeScanningInstance(inst)
	_, err := tx.Exec(`
		INSERT INTO code_scanning_alert_instances(
			repo_id, alert_number, ordinal, ref, commit_sha, path, start_line, end_line, start_column, end_column,
			state, category, classifications, analysis_key, environment
		)
		VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, repoID, alertNumber, snapshot.ref, snapshot.commitSHA, snapshot.path, snapshot.startLine, snapshot.endLine,
		snapshot.startColumn, snapshot.endColumn, snapshot.state, snapshot.category, snapshot.classifications,
		mostRecentAnalysisKey(inst), mostRecentEnvironment(inst))
	return err
}

func ingestSecretScanningAlerts(db *sql.DB, repoIDByName map[string]int64, alerts []*github.SecretScanningAlert) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO secret_scanning_alerts(
			repo_id, alert_number, state, secret_type, resolution, created_at, updated_at, resolved_at,
			url, html_url, locations_url, secret_type_display_name, secret, is_base64_encoded, multi_repo, publicly_leaked,
			push_protection_bypassed,
			push_protection_bypassed_at, resolution_comment, push_protection_bypass_request_comment,
			push_protection_bypass_request_html_url, validity, has_more_locations
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
		)
		if err != nil {
			return err
		}
		if err := upsertSecretScanningFirstLocationTx(tx, repoID, a.GetNumber(), a.GetFirstLocationDetected()); err != nil {
			return err
		}
		inserted++
	}
	log.Printf("secret scanning ingest summary: total=%d inserted=%d skipped_repo=%d", len(alerts), inserted, skippedRepo)

	return tx.Commit()
}

func upsertSecretScanningFirstLocationTx(tx *sql.Tx, repoID int64, alertNumber int, loc *github.SecretScanningAlertLocationDetails) error {
	if _, err := tx.Exec(`DELETE FROM secret_scanning_alert_locations WHERE repo_id = ? AND alert_number = ?`, repoID, alertNumber); err != nil {
		return err
	}
	if loc == nil {
		return nil
	}
	_, err := tx.Exec(`
		INSERT INTO secret_scanning_alert_locations(
			repo_id, alert_number, ordinal, path, start_line, end_line, start_column, end_column,
			blob_sha, blob_url, commit_sha, commit_url, pull_request_comment_url
		)
		VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, repoID, alertNumber, loc.GetPath(), nullableIntPtr(loc.Startline), nullableIntPtr(loc.EndLine), nullableIntPtr(loc.StartColumn),
		nullableIntPtr(loc.EndColumn), loc.GetBlobSHA(), loc.GetBlobURL(), loc.GetCommitSHA(), loc.GetCommitURL(), loc.GetPullRequestCommentURL())
	return err
}

func upsertDependabotAdvisoryTx(tx *sql.Tx, repoID int64, a *github.DependabotAlert) error {
	if a == nil {
		return nil
	}
	alertNumber := a.GetNumber()
	adv := a.GetSecurityAdvisory()
	advisoryID, err := upsertSecurityAdvisoryTx(tx, adv)
	if err != nil {
		return err
	}
	if adv == nil || advisoryID == 0 {
		return nil
	}
	if advisoryID != 0 {
		if _, err := tx.Exec(`
			INSERT INTO dependabot_alert_advisories(repo_id, alert_number, advisory_id)
			VALUES (?, ?, ?)
			ON CONFLICT(repo_id, alert_number) DO UPDATE SET advisory_id = excluded.advisory_id
		`, repoID, alertNumber, advisoryID); err != nil {
			return err
		}
	}

	for _, table := range []string{
		"security_advisory_vulnerabilities",
		"security_advisory_references",
		"security_advisory_cwes",
	} {
		if _, err := tx.Exec(
			fmt.Sprintf("DELETE FROM %s WHERE advisory_id = ?", table),
			advisoryID,
		); err != nil {
			return err
		}
	}

	packageOrdinals := make(map[int64]int)
	for _, v := range adv.Vulnerabilities {
		if v == nil {
			continue
		}
		pkg := v.GetPackage()
		packageID, err := upsertPackageTx(tx, pkg.GetEcosystem(), pkg.GetName(), "", "", "", "", "", "", nil)
		if err != nil {
			return err
		}
		packageKeyID := int64(-1)
		if packageID != 0 {
			packageKeyID = packageID
		}
		packageOrdinals[packageKeyID]++
		packageOrdinal := packageOrdinals[packageKeyID]
		_, err = tx.Exec(`
				INSERT INTO security_advisory_vulnerabilities(
					advisory_id, package_key_id, package_ordinal, severity, vulnerable_version_range,
					first_patched_version
				) VALUES (?, ?, ?, ?, ?, ?)
			`, advisoryID, packageKeyID, packageOrdinal, v.GetSeverity(),
			v.GetVulnerableVersionRange(), v.GetFirstPatchedVersion().GetIdentifier())
		if err != nil {
			return err
		}
	}

	for i, ref := range adv.References {
		if ref == nil {
			continue
		}
		referenceID, err := upsertAdvisoryReferenceTx(tx, ref.GetURL())
		if err != nil {
			return err
		}
		_, err = tx.Exec(`
				INSERT INTO security_advisory_references(advisory_id, reference_id, ref_num)
				VALUES (?, ?, ?)
				ON CONFLICT(advisory_id, reference_id) DO NOTHING
			`, advisoryID, referenceID, i+1)
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
		if err := upsertCWETx(tx, cweID, cwe.GetName()); err != nil {
			return err
		}
		_, err := tx.Exec(`
				INSERT INTO security_advisory_cwes(advisory_id, cwe_id)
				VALUES (?, ?)
				ON CONFLICT(advisory_id, cwe_id) DO NOTHING
			`, advisoryID, cweID)
		if err != nil {
			return err
		}
	}

	return nil
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
		FROM security_advisories
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
		if adv.CVSS != nil {
			cvssScore = floatPtrToValue(adv.CVSS.Score)
			cvssVector = adv.CVSS.GetVectorString()
		}
		epssPercentage = epssPercentageValue(adv.EPSS)
		epssPercentile = epssPercentileValue(adv.EPSS)
		publishedAt = formatGitHubTimePtr(adv.PublishedAt)
		updatedAt = formatGitHubTimePtr(adv.UpdatedAt)
		withdrawnAt = formatGitHubTimePtr(adv.WithdrawnAt)
		summary = adv.GetSummary()
		description = adv.GetDescription()
		severity = adv.GetSeverity()
	}

	if existingID != 0 {
		_, err = tx.Exec(`
			UPDATE security_advisories
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
		INSERT INTO security_advisories(
			ghsa_id, cve_id, summary, description, severity, cvss_score,
			cvss_vector_string, epss_percentage, epss_percentile, published_at, updated_at, withdrawn_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, ghsaID, cveID, summary, description, severity, cvssScore, cvssVector, epssPercentage, epssPercentile, publishedAt, updatedAt, withdrawnAt)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
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

func upsertCWETx(tx *sql.Tx, cweID, name string) error {
	_, err := tx.Exec(`
		INSERT INTO cwes(cwe_id, name)
		VALUES (?, ?)
		ON CONFLICT(cwe_id) DO UPDATE SET name = excluded.name
	`, cweID, name)
	return err
}
