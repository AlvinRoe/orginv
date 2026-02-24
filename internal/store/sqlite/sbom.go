package sqlite

import (
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

func ingestSBOM(db *sql.DB, repoID int64, sbom *github.SBOM) error {
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
		return err
	}

	var sbomID int64
	if err := tx.QueryRow(`SELECT sbom_id FROM sbom WHERE repo_id = ?`, repoID).Scan(&sbomID); err != nil {
		return err
	}

	if _, err := tx.Exec(`
		DELETE FROM sbom_packages WHERE sbom_id = ?;
		DELETE FROM sbom_package_external_refs WHERE sbom_id = ?;
		DELETE FROM sbom_relationships WHERE sbom_id = ?;
	`, sbomID, sbomID, sbomID); err != nil {
		return err
	}

	repoPackageStmt, err := tx.Prepare(`
		INSERT INTO repo_packages(repo_id, package_id, source)
		VALUES (?, ?, 'sbom')
		ON CONFLICT(repo_id, package_id, source) DO NOTHING
	`)
	if err != nil {
		return err
	}
	defer repoPackageStmt.Close()

	sbomDocPackageStmt, err := tx.Prepare(`
		INSERT INTO sbom_packages(
			sbom_id, spdx_package_id, package_id, license_concluded, download_location
		)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(sbom_id, spdx_package_id) DO UPDATE SET
			package_id = excluded.package_id,
			license_concluded = excluded.license_concluded,
			download_location = excluded.download_location
	`)
	if err != nil {
		return err
	}
	defer sbomDocPackageStmt.Close()

	externalRefStmt, err := tx.Prepare(`
		INSERT INTO sbom_package_external_refs(
			sbom_id, package_id, reference_category, reference_type, reference_locator
		) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT DO NOTHING
	`)
	if err != nil {
		return err
	}
	defer externalRefStmt.Close()

	relationshipStmt, err := tx.Prepare(`
		INSERT INTO sbom_relationships(
			sbom_id, from_package_id, to_package_id, relationship_type
		)
		VALUES (?, ?, ?, ?)
		ON CONFLICT DO NOTHING
	`)
	if err != nil {
		return err
	}
	defer relationshipStmt.Close()

	packageBySPDX := make(map[string]int64, len(doc.Packages))
	for i, pkg := range doc.Packages {
		if pkg == nil {
			continue
		}
		purl := extractPURLFromDependency(pkg)
		ecosystem := ecosystemFromPURL(purl)
		if ecosystem == "" {
			ecosystem = "unknown"
		}
		packageName := strings.TrimSpace(pkg.GetName())
		if packageName == "" {
			packageName = firstNonEmpty(strings.TrimSpace(purl), strings.TrimSpace(pkg.GetSPDXID()), fmt.Sprintf("unnamed-package-%d", i+1))
		}
		packageID, err := upsertPackageTx(
			tx,
			ecosystem,
			packageName,
			pkg.GetVersionInfo(),
			purl,
			firstNonEmpty(pkg.GetLicenseConcluded(), pkg.GetLicenseDeclared()),
			"",
			pkg.GetLicenseDeclared(),
			normalizeSBOMDownloadLocation(pkg.GetDownloadLocation()),
			boolPtrToIntPtr(pkg.FilesAnalyzed),
		)
		if err != nil {
			return fmt.Errorf("sbom package upsert failed (repo_id=%d spdx=%q ecosystem=%q name=%q version=%q purl=%q): %w", repoID, pkg.GetSPDXID(), ecosystem, packageName, pkg.GetVersionInfo(), purl, err)
		}
		if packageID == 0 {
			return fmt.Errorf("sbom package id is zero (repo_id=%d spdx=%q ecosystem=%q name=%q version=%q purl=%q)", repoID, pkg.GetSPDXID(), ecosystem, packageName, pkg.GetVersionInfo(), purl)
		}
		if spdxID := strings.TrimSpace(pkg.GetSPDXID()); spdxID != "" {
			packageBySPDX[spdxID] = packageID
		}
		if _, err := repoPackageStmt.Exec(repoID, packageID); err != nil {
			return fmt.Errorf("sbom repo_packages insert failed (repo_id=%d package_id=%d): %w", repoID, packageID, err)
		}

		if _, err := sbomDocPackageStmt.Exec(
			sbomID,
			pkg.GetSPDXID(),
			packageID,
			pkg.GetLicenseConcluded(),
			normalizeSBOMDownloadLocation(pkg.GetDownloadLocation()),
		); err != nil {
			return fmt.Errorf("sbom document package insert failed (repo_id=%d sbom_id=%d spdx=%q package_id=%d): %w", repoID, sbomID, pkg.GetSPDXID(), packageID, err)
		}

		for _, ref := range pkg.ExternalRefs {
			if ref == nil {
				continue
			}
			_, err := externalRefStmt.Exec(sbomID, packageID, ref.ReferenceCategory, ref.ReferenceType, ref.ReferenceLocator)
			if err != nil {
				return fmt.Errorf("sbom external ref insert failed (repo_id=%d sbom_id=%d package_id=%d ref_type=%q locator=%q): %w", repoID, sbomID, packageID, ref.ReferenceType, ref.ReferenceLocator, err)
			}
		}
	}

	for _, rel := range doc.Relationships {
		if rel == nil {
			continue
		}
		fromID, okFrom := packageBySPDX[rel.SPDXElementID]
		toID, okTo := packageBySPDX[rel.RelatedSPDXElement]
		if !okFrom && !okTo {
			continue
		}
		_, err := relationshipStmt.Exec(
			sbomID,
			nullableInt64(okFrom, fromID),
			nullableInt64(okTo, toID),
			rel.RelationshipType,
		)
		if err != nil {
			return fmt.Errorf("sbom relationship insert failed (repo_id=%d sbom_id=%d from_spdx=%q to_spdx=%q from_package_id=%v to_package_id=%v): %w", repoID, sbomID, rel.SPDXElementID, rel.RelatedSPDXElement, nullableInt64(okFrom, fromID), nullableInt64(okTo, toID), err)
		}
	}

	return tx.Commit()
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
	res, err := tx.Exec(`
		INSERT INTO packages(ecosystem, name, version, purl, license, supplier, license_declared, download_location, files_analyzed)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ecosystem, name, version, purl) DO NOTHING
	`, ecosystem, name, version, purl, license, supplier, licenseDeclared, downloadLocation, filesAnalyzed)
	if err != nil {
		return 0, err
	}
	_, _ = res.RowsAffected()
	var packageID int64
	if err := tx.QueryRow(`
		SELECT package_id FROM packages
		WHERE ecosystem = ? AND name = ? AND version = ? AND purl = ?
	`, ecosystem, name, version, purl).Scan(&packageID); err != nil {
		return 0, err
	}
	_, err = tx.Exec(`
		UPDATE packages
		SET
			license = COALESCE(NULLIF(?, ''), license),
			supplier = COALESCE(NULLIF(?, ''), supplier),
			license_declared = COALESCE(NULLIF(?, ''), license_declared),
			download_location = COALESCE(NULLIF(?, ''), download_location),
			files_analyzed = COALESCE(?, files_analyzed)
		WHERE package_id = ?
	`, license, supplier, licenseDeclared, downloadLocation, filesAnalyzed, packageID)
	if err != nil {
		return 0, err
	}
	return packageID, nil
}
