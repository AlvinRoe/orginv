package sqlite

import (
	"context"
)

type ReportData struct {
	Headers []string
	Records [][]string
}

func (s *Store) QueryReportData(ctx context.Context) (ReportData, error) {
	query := `
		SELECT
			r.repo_id,
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
				r.advanced_security_status,
				r.secret_scanning_status,
				r.secret_scanning_push_protection_status,
				r.dependabot_security_updates_status,
				r.immerse_ask_id,
				r.immerse_jfrog_project_key,
				r.immerse_sast_compliant,
				(SELECT sd.spdx_id FROM sbom sd WHERE sd.repo_id = r.repo_id LIMIT 1) AS sbom_spdx_id,
				(SELECT sd.spdx_version FROM sbom sd WHERE sd.repo_id = r.repo_id LIMIT 1) AS sbom_spdx_version,
				(SELECT sd.document_name FROM sbom sd WHERE sd.repo_id = r.repo_id LIMIT 1) AS sbom_document_name,
				(SELECT sd.data_license FROM sbom sd WHERE sd.repo_id = r.repo_id LIMIT 1) AS sbom_data_license,
				(SELECT sd.document_namespace FROM sbom sd WHERE sd.repo_id = r.repo_id LIMIT 1) AS sbom_document_namespace,
				(SELECT sd.generated_at FROM sbom sd WHERE sd.repo_id = r.repo_id LIMIT 1) AS sbom_generated_at,
				(SELECT sd.creation_creators FROM sbom sd WHERE sd.repo_id = r.repo_id LIMIT 1) AS sbom_creation_creators,
				(SELECT sd.document_describes_count FROM sbom sd WHERE sd.repo_id = r.repo_id LIMIT 1) AS sbom_document_describes_count,
				(SELECT sd.package_count FROM sbom sd WHERE sd.repo_id = r.repo_id LIMIT 1) AS sbom_package_count,
				(SELECT sd.relationship_count FROM sbom sd WHERE sd.repo_id = r.repo_id LIMIT 1) AS sbom_relationship_count,
			(SELECT COUNT(1) FROM repo_packages rp WHERE rp.repo_id = r.repo_id) AS dependency_count,
			(
				SELECT COALESCE(group_concat(
					'package_id=' || p.package_id ||
					';ecosystem=' || COALESCE(p.ecosystem, '') ||
					';name=' || COALESCE(p.name, '') ||
					';version=' || COALESCE(p.version, '') ||
					';purl=' || COALESCE(p.purl, '') ||
					';license=' || COALESCE(p.license, '') ||
					';supplier=' || COALESCE(p.supplier, ''),
					char(10)
				), '')
				FROM repo_packages rp
				JOIN packages p ON p.package_id = rp.package_id
				WHERE rp.repo_id = r.repo_id
			) AS dependency_details,
			(SELECT COUNT(1) FROM dependabot_alerts da WHERE da.repo_id = r.repo_id AND lower(da.state) = 'open') AS open_dependabot_alerts,
			(SELECT COUNT(1) FROM dependabot_alerts da WHERE da.repo_id = r.repo_id AND lower(da.state) = 'open' AND lower(da.severity) = 'critical') AS open_critical_dependabot_alerts,
			(SELECT COUNT(1) FROM dependabot_alerts da WHERE da.repo_id = r.repo_id) AS total_dependabot_alerts,
			(
				SELECT COALESCE(group_concat(
					'alert_number=' || da.alert_number ||
					';state=' || COALESCE(da.state, '') ||
					';severity=' || COALESCE(da.severity, '') ||
					';ecosystem=' || COALESCE(p.ecosystem, '') ||
					';package_name=' || COALESCE(p.name, '') ||
					';manifest_path=' || COALESCE(da.manifest_path, '') ||
					';created_at=' || COALESCE(da.created_at, '') ||
					';updated_at=' || COALESCE(da.updated_at, '') ||
					';fixed_at=' || COALESCE(da.fixed_at, '') ||
					';dismissed_reason=' || COALESCE(da.dismissed_reason, '') ||
					';package_id=' || COALESCE(CAST(da.package_id AS TEXT), ''),
					char(10)
				), '')
				FROM dependabot_alerts da
				LEFT JOIN packages p ON p.package_id = da.package_id
				WHERE da.repo_id = r.repo_id
			) AS dependabot_alert_details,
			(SELECT COUNT(1) FROM code_scanning_alerts ca WHERE ca.repo_id = r.repo_id AND lower(ca.state) = 'open') AS open_code_scanning_alerts,
			(SELECT COUNT(1) FROM code_scanning_alerts ca WHERE ca.repo_id = r.repo_id) AS total_code_scanning_alerts,
			(
				SELECT COALESCE(group_concat(
					'alert_number=' || ca.alert_number ||
					';state=' || COALESCE(ca.state, '') ||
						';severity=' || COALESCE(ca.severity, '') ||
						';created_at=' || COALESCE(ca.created_at, '') ||
						';fixed_at=' || COALESCE(ca.fixed_at, '') ||
						';most_recent_ref=' || COALESCE(ca.ref, '') ||
						';most_recent_commit_sha=' || COALESCE(ca.commit_sha, '') ||
						';most_recent_path=' || COALESCE(ca.path, '') ||
						';most_recent_state=' || COALESCE(ca.most_recent_state, ''),
						char(10)
					), '')
					FROM code_scanning_alerts ca
				WHERE ca.repo_id = r.repo_id
			) AS code_scanning_alert_details,
			(SELECT COUNT(1) FROM secret_alerts sa WHERE sa.repo_id = r.repo_id AND lower(sa.state) = 'open') AS open_secret_scanning_alerts,
			(SELECT COUNT(1) FROM secret_alerts sa WHERE sa.repo_id = r.repo_id) AS total_secret_scanning_alerts,
			(
				SELECT COALESCE(group_concat(
					'alert_number=' || sa.alert_number ||
					';state=' || COALESCE(sa.state, '') ||
					';secret_type=' || COALESCE(sa.secret_type, '') ||
					';resolution=' || COALESCE(sa.resolution, '') ||
					';created_at=' || COALESCE(sa.created_at, '') ||
					';updated_at=' || COALESCE(sa.updated_at, '') ||
					';resolved_at=' || COALESCE(sa.resolved_at, '') ||
					';first_location_path=' || COALESCE(sa.path, ''),
					char(10)
				), '')
				FROM secret_alerts sa
				WHERE sa.repo_id = r.repo_id
			) AS secret_scanning_alert_details
			FROM repos r
			WHERE lower(r.name) != '.github'
		ORDER BY open_critical_dependabot_alerts DESC, open_dependabot_alerts DESC, r.full_name ASC
	`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return ReportData{}, err
	}
	defer rows.Close()

	headers, err := rows.Columns()
	if err != nil {
		return ReportData{}, err
	}

	records := make([][]string, 0, 256)
	for rows.Next() {
		vals := make([]interface{}, len(headers))
		valPtrs := make([]interface{}, len(headers))
		for i := range vals {
			valPtrs[i] = &vals[i]
		}
		if err := rows.Scan(valPtrs...); err != nil {
			return ReportData{}, err
		}
		record := make([]string, len(headers))
		for i, v := range vals {
			record[i] = stringifyDBValue(v)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return ReportData{}, err
	}
	return ReportData{Headers: headers, Records: records}, nil
}
