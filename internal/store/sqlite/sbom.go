package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

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

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := upsertSBOMDocumentTx(ctx, tx, repoID, doc); err != nil {
		return err
	}

	for i, pkg := range doc.Packages {
		if pkg == nil {
			continue
		}
		identity := sbomIdentityFromPackage(i, pkg)
		packageVersionID, err := upsertPackageTx(
			tx,
			identity.ecosystem,
			identity.name,
			identity.version,
			identity.purl,
			identity.licenseConcluded,
			"",
			identity.licenseDeclared,
			identity.downloadLocation,
			identity.filesAnalyzed,
		)
		if err != nil {
			return fmt.Errorf("sbom package upsert failed (repo_id=%d spdx=%q ecosystem=%q name=%q version=%q purl=%q): %w", repoID, pkg.GetSPDXID(), identity.ecosystem, identity.name, identity.version, identity.purl, err)
		}
		if packageVersionID == 0 {
			return fmt.Errorf("sbom package version id is zero (repo_id=%d spdx=%q ecosystem=%q name=%q version=%q purl=%q)", repoID, pkg.GetSPDXID(), identity.ecosystem, identity.name, identity.version, identity.purl)
		}
	}

	return tx.Commit()
}

func (s *Store) IngestSBOMLinks(ctx context.Context, repoID int64, sbom *github.SBOM) error {
	if sbom == nil || sbom.SBOM == nil {
		return nil
	}
	doc := sbom.SBOM

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	sbomID, err := upsertSBOMDocumentTx(ctx, tx, repoID, doc)
	if err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `
		DELETE FROM sbom_packages WHERE sbom_id = ?;
		DELETE FROM sbom_package_external_refs WHERE sbom_id = ?;
		DELETE FROM sbom_relationships WHERE sbom_id = ?;
	`, sbomID, sbomID, sbomID); err != nil {
		return err
	}

	repoPackageVersionStmt, err := tx.PrepareContext(ctx, `
		INSERT INTO repo_package_versions(repo_id, package_version_id, source)
		VALUES (?, ?, 'sbom')
		ON CONFLICT(repo_id, package_version_id, source) DO NOTHING
	`)
	if err != nil {
		return err
	}
	defer repoPackageVersionStmt.Close()

	sbomDocPackageStmt, err := tx.PrepareContext(ctx, `
		INSERT INTO sbom_packages(
			sbom_id, spdx_package_id, package_version_id, license_concluded, download_location
		)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(sbom_id, spdx_package_id) DO UPDATE SET
			package_version_id = excluded.package_version_id,
			license_concluded = excluded.license_concluded,
			download_location = excluded.download_location
	`)
	if err != nil {
		return err
	}
	defer sbomDocPackageStmt.Close()

	externalRefStmt, err := tx.PrepareContext(ctx, `
		INSERT INTO sbom_package_external_refs(
			sbom_id, package_version_id, reference_category, reference_type, reference_locator
		) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT DO NOTHING
	`)
	if err != nil {
		return err
	}
	defer externalRefStmt.Close()

	relationshipStmt, err := tx.PrepareContext(ctx, `
		INSERT INTO sbom_relationships(
			sbom_id, from_package_version_id, to_package_version_id, relationship_type
		)
		VALUES (?, ?, ?, ?)
		ON CONFLICT DO NOTHING
	`)
	if err != nil {
		return err
	}
	defer relationshipStmt.Close()

	packageVersionBySPDX := make(map[string]int64, len(doc.Packages))
	for i, pkg := range doc.Packages {
		if pkg == nil {
			continue
		}
		identity := sbomIdentityFromPackage(i, pkg)
		packageVersionID, err := resolvePackageVersionIDTx(tx, identity.ecosystem, identity.name, identity.version, identity.purl)
		if err != nil {
			return fmt.Errorf("sbom package version lookup failed (repo_id=%d spdx=%q ecosystem=%q name=%q version=%q purl=%q): %w", repoID, pkg.GetSPDXID(), identity.ecosystem, identity.name, identity.version, identity.purl, err)
		}
		if packageVersionID == 0 {
			return fmt.Errorf("sbom package version not found for links (repo_id=%d spdx=%q ecosystem=%q name=%q version=%q purl=%q)", repoID, pkg.GetSPDXID(), identity.ecosystem, identity.name, identity.version, identity.purl)
		}
		if spdxID := strings.TrimSpace(pkg.GetSPDXID()); spdxID != "" {
			packageVersionBySPDX[spdxID] = packageVersionID
		}
		if _, err := repoPackageVersionStmt.ExecContext(ctx, repoID, packageVersionID); err != nil {
			return fmt.Errorf("sbom repo_package_versions insert failed (repo_id=%d package_version_id=%d): %w", repoID, packageVersionID, err)
		}

		if _, err := sbomDocPackageStmt.ExecContext(
			ctx,
			sbomID,
			pkg.GetSPDXID(),
			packageVersionID,
			pkg.GetLicenseConcluded(),
			identity.downloadLocation,
		); err != nil {
			return fmt.Errorf("sbom document package insert failed (repo_id=%d sbom_id=%d spdx=%q package_version_id=%d): %w", repoID, sbomID, pkg.GetSPDXID(), packageVersionID, err)
		}

		for _, ref := range pkg.ExternalRefs {
			if ref == nil {
				continue
			}
			if _, err := externalRefStmt.ExecContext(ctx, sbomID, packageVersionID, ref.ReferenceCategory, ref.ReferenceType, ref.ReferenceLocator); err != nil {
				return fmt.Errorf("sbom external ref insert failed (repo_id=%d sbom_id=%d package_version_id=%d ref_type=%q locator=%q): %w", repoID, sbomID, packageVersionID, ref.ReferenceType, ref.ReferenceLocator, err)
			}
		}
	}

	for _, rel := range doc.Relationships {
		if rel == nil {
			continue
		}
		fromID, okFrom := packageVersionBySPDX[rel.SPDXElementID]
		toID, okTo := packageVersionBySPDX[rel.RelatedSPDXElement]
		if !okFrom && !okTo {
			continue
		}
		if _, err := relationshipStmt.ExecContext(
			ctx,
			sbomID,
			nullableInt64(okFrom, fromID),
			nullableInt64(okTo, toID),
			rel.RelationshipType,
		); err != nil {
			return fmt.Errorf("sbom relationship insert failed (repo_id=%d sbom_id=%d from_spdx=%q to_spdx=%q from_package_version_id=%v to_package_version_id=%v): %w", repoID, sbomID, rel.SPDXElementID, rel.RelatedSPDXElement, nullableInt64(okFrom, fromID), nullableInt64(okTo, toID), err)
		}
	}

	return tx.Commit()
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
