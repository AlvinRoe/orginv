package sqlite

import (
	"fmt"
	"strconv"
	"strings"
)

func sqlString(v string) string {
	return "'" + strings.ReplaceAll(v, "'", "''") + "'"
}

func sqlValue(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return "NULL"
	case string:
		return sqlString(t)
	case *string:
		if t == nil {
			return "NULL"
		}
		return sqlString(*t)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		if t {
			return "1"
		}
		return "0"
	default:
		return sqlString(fmt.Sprint(v))
	}
}

func sqlNullableString(v string) string {
	if strings.TrimSpace(v) == "" {
		return "NULL"
	}
	return sqlString(v)
}

func advisoryIDSubquery(ghsaID, cveID string) string {
	return fmt.Sprintf(
		"(SELECT advisory_id FROM advisories WHERE ghsa_id = %s AND cve_id = %s LIMIT 1)",
		sqlString(strings.TrimSpace(ghsaID)),
		sqlString(strings.TrimSpace(cveID)),
	)
}

func packageIDSubquery(ecosystem, name string) string {
	ecosystem = strings.TrimSpace(ecosystem)
	if ecosystem == "" {
		ecosystem = "unknown"
	}
	return fmt.Sprintf(
		"(SELECT package_id FROM packages WHERE ecosystem = %s AND name = %s LIMIT 1)",
		sqlString(ecosystem),
		sqlString(strings.TrimSpace(name)),
	)
}

func packageVersionIDSubquery(ecosystem, name, version, purl string) string {
	return fmt.Sprintf(
		`(
			SELECT pv.package_version_id
			FROM package_versions pv
			JOIN packages p ON p.package_id = pv.package_id
			WHERE p.ecosystem = %s AND p.name = %s AND pv.version = %s AND pv.purl = %s
			LIMIT 1
		)`,
		sqlString(defaultEcosystem(ecosystem)),
		sqlString(strings.TrimSpace(name)),
		sqlString(strings.TrimSpace(version)),
		sqlString(strings.TrimSpace(purl)),
	)
}

func sbomIDSubquery(repoID int64) string {
	return fmt.Sprintf("(SELECT sbom_id FROM sbom WHERE repo_id = %d LIMIT 1)", repoID)
}

func defaultEcosystem(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "unknown"
	}
	return v
}
