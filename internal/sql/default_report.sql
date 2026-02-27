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
	(SELECT COUNT(1) FROM repo_package_versions rpv WHERE rpv.repo_id = r.repo_id) AS dependency_count,
	(
		SELECT COALESCE(group_concat(
			'package_id=' || p.package_id ||
			';package_version_id=' || pv.package_version_id ||
			';ecosystem=' || COALESCE(p.ecosystem, '') ||
			';name=' || COALESCE(p.name, '') ||
			';version=' || COALESCE(pv.version, '') ||
			';purl=' || COALESCE(pv.purl, '') ||
			';license=' || COALESCE(pv.license, '') ||
			';supplier=' || COALESCE(pv.supplier, ''),
			char(10)
		), '')
		FROM repo_package_versions rpv
		JOIN package_versions pv ON pv.package_version_id = rpv.package_version_id
		JOIN packages p ON p.package_id = pv.package_id
		WHERE rpv.repo_id = r.repo_id
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
			';package_version_id=' || COALESCE(CAST(da.package_version_id AS TEXT), '') ||
			';package_version=' || COALESCE(pv.version, '') ||
			';package_purl=' || COALESCE(pv.purl, '') ||
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
		LEFT JOIN package_versions pv ON pv.package_version_id = da.package_version_id
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
