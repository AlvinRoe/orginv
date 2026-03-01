package sqlite

import (
	"context"
	"fmt"

	"github.com/AlvinRoe/orginv/internal/store/sqlite/sqlbatch"
)

type vulnerableRepoPackageRow struct {
	repoID                 int64
	packageVersionID       int64
	advisoryID             int64
	packageID              int64
	ecosystem              string
	packageName            string
	packageVersion         string
	vulnerableVersionRange string
	firstPatchedVersion    string
	advisorySeverity       string
	ghsaID                 string
	cveID                  string
}

func (s *Store) RefreshVulnerableRepoPackages(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `
		SELECT
			rpv.repo_id,
			pv.package_version_id,
			av.advisory_id,
			p.package_id,
			p.ecosystem,
			p.name,
			pv.version,
			COALESCE(av.vulnerable_version_range, ''),
			COALESCE(av.first_patched_version, ''),
			COALESCE(a.severity, ''),
			COALESCE(a.ghsa_id, ''),
			COALESCE(a.cve_id, '')
		FROM repo_package_versions rpv
		JOIN package_versions pv ON pv.package_version_id = rpv.package_version_id
		JOIN packages p ON p.package_id = pv.package_id
		JOIN advisory_vulnerabilities av ON av.package_id = p.package_id
		JOIN advisories a ON a.advisory_id = av.advisory_id
		WHERE COALESCE(av.vulnerable_version_range, '') != ''
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	batch := sqlbatch.New()
	batch.Add("vulnerable_repo_packages", `DELETE FROM vulnerable_repo_packages`)

	for rows.Next() {
		var row vulnerableRepoPackageRow
		if err := rows.Scan(
			&row.repoID,
			&row.packageVersionID,
			&row.advisoryID,
			&row.packageID,
			&row.ecosystem,
			&row.packageName,
			&row.packageVersion,
			&row.vulnerableVersionRange,
			&row.firstPatchedVersion,
			&row.advisorySeverity,
			&row.ghsaID,
			&row.cveID,
		); err != nil {
			return err
		}
		if !vulnerableRangeMatches(row.packageVersion, row.vulnerableVersionRange) {
			continue
		}
		batch.Add("vulnerable_repo_packages", buildVulnerableRepoPackageInsertSQL(row))
	}
	if err := rows.Err(); err != nil {
		return err
	}

	return s.flushBatch(ctx, "vulnerable repo packages", batch)
}

func buildVulnerableRepoPackageInsertSQL(row vulnerableRepoPackageRow) string {
	return fmt.Sprintf(
		`INSERT INTO vulnerable_repo_packages(
			repo_id, package_version_id, advisory_id, package_id, ecosystem, package_name,
			package_version, vulnerable_version_range, first_patched_version, advisory_severity, ghsa_id, cve_id
		) VALUES (
			%d, %d, %d, %d, %s, %s, %s, %s, %s, %s, %s, %s
		)
		ON CONFLICT(repo_id, package_version_id, advisory_id, vulnerable_version_range) DO UPDATE SET
			first_patched_version = excluded.first_patched_version,
			advisory_severity = excluded.advisory_severity,
			ghsa_id = excluded.ghsa_id,
			cve_id = excluded.cve_id`,
		row.repoID,
		row.packageVersionID,
		row.advisoryID,
		row.packageID,
		sqlString(row.ecosystem),
		sqlString(row.packageName),
		sqlString(row.packageVersion),
		sqlString(row.vulnerableVersionRange),
		sqlString(row.firstPatchedVersion),
		sqlString(row.advisorySeverity),
		sqlString(row.ghsaID),
		sqlString(row.cveID),
	)
}
