package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/AlvinRoe/orginv/internal/store/sqlite/sqlbatch"
	"github.com/google/go-github/v82/github"
)

func normalizeSBOMDownloadLocation(v string) string {
	v = strings.TrimSpace(v)
	if strings.EqualFold(v, "NOASSERTION") {
		return ""
	}
	return v
}

type sbomPackageIdentity struct {
	ecosystem        string
	name             string
	version          string
	purl             string
	licenseConcluded string
	licenseDeclared  string
	downloadLocation string
	filesAnalyzed    interface{}
}

func sbomIdentityFromPackage(index int, pkg *github.RepoDependencies) sbomPackageIdentity {
	if pkg == nil {
		return sbomPackageIdentity{}
	}
	purl := extractPURLFromDependency(pkg)
	ecosystem := ecosystemFromPURL(purl)
	if ecosystem == "" {
		ecosystem = "unknown"
	}
	packageName := strings.TrimSpace(pkg.GetName())
	if packageName == "" {
		packageName = firstNonEmpty(strings.TrimSpace(purl), strings.TrimSpace(pkg.GetSPDXID()), fmt.Sprintf("unnamed-package-%d", index+1))
	}
	return sbomPackageIdentity{
		ecosystem:        ecosystem,
		name:             packageName,
		version:          pkg.GetVersionInfo(),
		purl:             purl,
		licenseConcluded: firstNonEmpty(pkg.GetLicenseConcluded(), pkg.GetLicenseDeclared()),
		licenseDeclared:  pkg.GetLicenseDeclared(),
		downloadLocation: normalizeSBOMDownloadLocation(pkg.GetDownloadLocation()),
		filesAnalyzed:    boolPtrToIntPtr(pkg.FilesAnalyzed),
	}
}

func (s *Store) IngestSBOM(ctx context.Context, repoID int64, sbom *github.SBOM) error {
	if err := s.IngestSBOMMain(ctx, repoID, sbom); err != nil {
		return err
	}
	return s.IngestSBOMLinks(ctx, repoID, sbom)
}

func (s *Store) IngestSBOMMain(ctx context.Context, repoID int64, sbom *github.SBOM) error {
	if sbom == nil || sbom.SBOM == nil {
		return nil
	}
	doc := sbom.SBOM
	batch := sqlbatch.New()
	batch.Add("sbom", buildSBOMDocumentUpsertSQL(repoID, doc))

	for i, pkg := range doc.Packages {
		if pkg == nil {
			continue
		}
		identity := sbomIdentityFromPackage(i, pkg)
		batch.Add("packages", buildPackageIdentityUpsertSQL(identity.ecosystem, identity.name))
		batch.Add("package_versions", buildPackageVersionUpsertSQL(identity))
	}

	return s.flushBatch(ctx, fmt.Sprintf("sbom main repo=%d", repoID), batch)
}

func (s *Store) IngestSBOMLinks(ctx context.Context, repoID int64, sbom *github.SBOM) error {
	if sbom == nil || sbom.SBOM == nil {
		return nil
	}
	doc := sbom.SBOM
	batch := sqlbatch.New()
	batch.Add("repo_package_versions", fmt.Sprintf(`DELETE FROM repo_package_versions WHERE repo_id = %d`, repoID))
	batch.Add("sbom_packages", fmt.Sprintf(`DELETE FROM sbom_packages WHERE sbom_id = %s`, sbomIDSubquery(repoID)))
	batch.Add("sbom_package_external_refs", fmt.Sprintf(`DELETE FROM sbom_package_external_refs WHERE sbom_id = %s`, sbomIDSubquery(repoID)))
	batch.Add("sbom_relationships", fmt.Sprintf(`DELETE FROM sbom_relationships WHERE sbom_id = %s`, sbomIDSubquery(repoID)))

	packageIdentityBySPDX := make(map[string]sbomPackageIdentity, len(doc.Packages))
	for i, pkg := range doc.Packages {
		if pkg == nil {
			continue
		}
		identity := sbomIdentityFromPackage(i, pkg)
		if spdxID := strings.TrimSpace(pkg.GetSPDXID()); spdxID != "" {
			packageIdentityBySPDX[spdxID] = identity
		}
		packageVersionExpr := packageVersionIDSubquery(identity.ecosystem, identity.name, identity.version, identity.purl)
		batch.Add("repo_package_versions", fmt.Sprintf(
			`INSERT INTO repo_package_versions(repo_id, package_version_id)
			VALUES (%d, %s)
			ON CONFLICT(repo_id, package_version_id) DO NOTHING`,
			repoID, packageVersionExpr,
		))
		batch.Add("sbom_packages", fmt.Sprintf(
			`INSERT INTO sbom_packages(
				sbom_id, spdx_package_id, package_version_id, license_concluded, download_location
			) VALUES (%s, %s, %s, %s, %s)
			ON CONFLICT(sbom_id, spdx_package_id) DO UPDATE SET
				package_version_id = excluded.package_version_id,
				license_concluded = excluded.license_concluded,
				download_location = excluded.download_location`,
			sbomIDSubquery(repoID),
			sqlString(pkg.GetSPDXID()),
			packageVersionExpr,
			sqlString(pkg.GetLicenseConcluded()),
			sqlString(identity.downloadLocation),
		))

		for _, ref := range pkg.ExternalRefs {
			if ref == nil {
				continue
			}
			batch.Add("sbom_package_external_refs", fmt.Sprintf(
				`INSERT INTO sbom_package_external_refs(
					sbom_id, package_version_id, reference_category, reference_type, reference_locator
				) VALUES (%s, %s, %s, %s, %s)
				ON CONFLICT DO NOTHING`,
				sbomIDSubquery(repoID),
				packageVersionExpr,
				sqlString(ref.ReferenceCategory),
				sqlString(ref.ReferenceType),
				sqlString(ref.ReferenceLocator),
			))
		}
	}

	for _, rel := range doc.Relationships {
		if rel == nil {
			continue
		}
		fromIdentity, okFrom := packageIdentityBySPDX[rel.SPDXElementID]
		toIdentity, okTo := packageIdentityBySPDX[rel.RelatedSPDXElement]
		if !okFrom && !okTo {
			continue
		}
		fromExpr := "NULL"
		if okFrom {
			fromExpr = packageVersionIDSubquery(fromIdentity.ecosystem, fromIdentity.name, fromIdentity.version, fromIdentity.purl)
		}
		toExpr := "NULL"
		if okTo {
			toExpr = packageVersionIDSubquery(toIdentity.ecosystem, toIdentity.name, toIdentity.version, toIdentity.purl)
		}
		batch.Add("sbom_relationships", fmt.Sprintf(
			`INSERT INTO sbom_relationships(
				sbom_id, from_package_version_id, to_package_version_id, relationship_type
			) VALUES (%s, %s, %s, %s)
			ON CONFLICT DO NOTHING`,
			sbomIDSubquery(repoID),
			fromExpr,
			toExpr,
			sqlString(rel.RelationshipType),
		))
	}

	return s.flushBatch(ctx, fmt.Sprintf("sbom links repo=%d", repoID), batch)
}

func buildSBOMDocumentUpsertSQL(repoID int64, doc *github.SBOMInfo) string {
	return fmt.Sprintf(
		`INSERT INTO sbom(
			repo_id, spdx_id, spdx_version, document_name, data_license,
			document_namespace, generated_at, creation_creators, document_describes_count, package_count, relationship_count
		) VALUES (
			%d, %s, %s, %s, %s, %s, %s, %s, %d, %d, %d
		)
		ON CONFLICT(repo_id) DO UPDATE SET
			spdx_id = excluded.spdx_id,
			spdx_version = excluded.spdx_version,
			document_name = excluded.document_name,
			data_license = excluded.data_license,
			document_namespace = excluded.document_namespace,
			generated_at = excluded.generated_at,
			creation_creators = excluded.creation_creators,
			document_describes_count = excluded.document_describes_count,
			package_count = excluded.package_count,
			relationship_count = excluded.relationship_count`,
		repoID,
		sqlString(doc.GetSPDXID()),
		sqlString(doc.GetSPDXVersion()),
		sqlString(doc.GetName()),
		sqlString(doc.GetDataLicense()),
		sqlString(doc.GetDocumentNamespace()),
		sqlString(sbomCreatedAt(doc)),
		sqlString(sbomCreators(doc)),
		len(doc.DocumentDescribes),
		len(doc.Packages),
		len(doc.Relationships),
	)
}

func buildPackageVersionUpsertSQL(identity sbomPackageIdentity) string {
	return fmt.Sprintf(
		`INSERT INTO package_versions(
			package_id, version, purl, license, supplier, license_declared, download_location, files_analyzed
		)
		SELECT package_id, %s, %s, %s, %s, %s, %s, %s
		FROM packages
		WHERE ecosystem = %s AND name = %s
		ON CONFLICT(package_id, version, purl) DO UPDATE SET
			license = COALESCE(NULLIF(excluded.license, ''), package_versions.license),
			supplier = COALESCE(NULLIF(excluded.supplier, ''), package_versions.supplier),
			license_declared = COALESCE(NULLIF(excluded.license_declared, ''), package_versions.license_declared),
			download_location = COALESCE(NULLIF(excluded.download_location, ''), package_versions.download_location),
			files_analyzed = COALESCE(excluded.files_analyzed, package_versions.files_analyzed)`,
		sqlString(identity.version),
		sqlString(identity.purl),
		sqlString(identity.licenseConcluded),
		sqlString(""),
		sqlString(identity.licenseDeclared),
		sqlString(identity.downloadLocation),
		sqlValue(identity.filesAnalyzed),
		sqlString(defaultEcosystem(identity.ecosystem)),
		sqlString(identity.name),
	)
}

func upsertSBOMDocumentTx(ctx context.Context, tx *sql.Tx, repoID int64, doc *github.SBOMInfo) (int64, error) {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO sbom(
			repo_id, spdx_id, spdx_version, document_name, data_license,
			document_namespace, generated_at, creation_creators, document_describes_count, package_count, relationship_count
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(repo_id) DO UPDATE SET
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
		return 0, err
	}

	var sbomID int64
	if err := tx.QueryRowContext(ctx, `SELECT sbom_id FROM sbom WHERE repo_id = ?`, repoID).Scan(&sbomID); err != nil {
		return 0, err
	}
	return sbomID, nil
}

func upsertPackageIdentityTx(tx *sql.Tx, ecosystem, name string) (int64, error) {
	ecosystem = safeStr(ecosystem)
	name = safeStr(name)
	if ecosystem == "" {
		ecosystem = "unknown"
	}
	if name == "" {
		return 0, nil
	}
	if _, err := tx.Exec(`
		INSERT INTO packages(ecosystem, name)
		VALUES (?, ?)
		ON CONFLICT(ecosystem, name) DO NOTHING
	`, ecosystem, name); err != nil {
		return 0, err
	}

	var packageID int64
	err := tx.QueryRow(`
		SELECT package_id FROM packages
		WHERE ecosystem = ? AND name = ?
		LIMIT 1
	`, ecosystem, name).Scan(&packageID)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return packageID, nil
}

func lookupPackageIdentityIDTx(tx *sql.Tx, ecosystem, name string) (int64, error) {
	ecosystem = safeStr(ecosystem)
	name = safeStr(name)
	if ecosystem == "" {
		ecosystem = "unknown"
	}
	if name == "" {
		return 0, nil
	}

	var packageID int64
	err := tx.QueryRow(`
		SELECT package_id FROM packages
		WHERE ecosystem = ? AND name = ?
		LIMIT 1
	`, ecosystem, name).Scan(&packageID)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return packageID, nil
}

func resolvePackageVersionIDTx(tx *sql.Tx, ecosystem, name, version, purl string) (int64, error) {
	ecosystem = safeStr(ecosystem)
	name = safeStr(name)
	version = safeStr(version)
	purl = safeStr(purl)
	if ecosystem == "" {
		ecosystem = "unknown"
	}
	if name == "" {
		return 0, nil
	}

	packageID, err := lookupPackageIdentityIDTx(tx, ecosystem, name)
	if err != nil || packageID == 0 {
		return packageID, err
	}

	var packageVersionID int64
	err = tx.QueryRow(`
		SELECT package_version_id FROM package_versions
		WHERE package_id = ? AND version = ? AND purl = ?
		LIMIT 1
	`, packageID, version, purl).Scan(&packageVersionID)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return packageVersionID, nil
}

func upsertPackageTx(tx *sql.Tx, ecosystem, name, version, purl, license, supplier, licenseDeclared, downloadLocation string, filesAnalyzed interface{}) (int64, error) {
	ecosystem = safeStr(ecosystem)
	name = safeStr(name)
	version = safeStr(version)
	purl = safeStr(purl)
	if ecosystem == "" {
		ecosystem = "unknown"
	}
	if name == "" {
		return 0, nil
	}

	packageID, err := upsertPackageIdentityTx(tx, ecosystem, name)
	if err != nil {
		return 0, err
	}
	if packageID == 0 {
		return 0, nil
	}

	if _, err := tx.Exec(`
		INSERT INTO package_versions(package_id, version, purl, license, supplier, license_declared, download_location, files_analyzed)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(package_id, version, purl) DO NOTHING
	`, packageID, version, purl, license, supplier, licenseDeclared, downloadLocation, filesAnalyzed); err != nil {
		return 0, err
	}

	var packageVersionID int64
	if err := tx.QueryRow(`
		SELECT package_version_id FROM package_versions
		WHERE package_id = ? AND version = ? AND purl = ?
	`, packageID, version, purl).Scan(&packageVersionID); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`
		UPDATE package_versions
		SET
			license = COALESCE(NULLIF(?, ''), license),
			supplier = COALESCE(NULLIF(?, ''), supplier),
			license_declared = COALESCE(NULLIF(?, ''), license_declared),
			download_location = COALESCE(NULLIF(?, ''), download_location),
			files_analyzed = COALESCE(?, files_analyzed)
		WHERE package_version_id = ?
	`, license, supplier, licenseDeclared, downloadLocation, filesAnalyzed, packageVersionID); err != nil {
		return 0, err
	}
	return packageVersionID, nil
}
