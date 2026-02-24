package sqlite

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-github/v82/github"
)

type codeScanningInstanceSnapshot struct {
	ref             string
	commitSHA       string
	path            string
	startLine       interface{}
	endLine         interface{}
	startColumn     interface{}
	endColumn       interface{}
	state           string
	category        string
	classifications string
}

func stringPtr(v string) *string {
	return &v
}

func resolveAlertRepoID(repoIDByName map[string]int64, repo *github.Repository) (int64, bool) {
	if repo != nil {
		if fullName := repo.GetFullName(); fullName != "" {
			if id, ok := repoIDByName[fullName]; ok {
				return id, true
			}
		}
		if name := repo.GetName(); name != "" {
			if id, ok := repoIDByName[name]; ok {
				return id, true
			}
		}
		if repoID := repo.GetID(); repoID != 0 {
			if id, ok := repoIDByName[repoIDKey(repoID)]; ok {
				return id, true
			}
		}
	}
	return 0, false
}

func dependabotAlertKey(a *github.DependabotAlert) string {
	if a == nil {
		return ""
	}
	repo := a.GetRepository()
	if repo != nil && repo.GetID() != 0 {
		return fmt.Sprintf("%d:%d", repo.GetID(), a.GetNumber())
	}
	return firstNonEmpty(a.GetHTMLURL(), a.GetURL(), fmt.Sprintf("unknown:%d", a.GetNumber()))
}

func codeScanningAlertKey(a *github.Alert) string {
	if a == nil {
		return ""
	}
	repo := a.GetRepository()
	if repo != nil && repo.GetID() != 0 {
		return fmt.Sprintf("%d:%d", repo.GetID(), a.GetNumber())
	}
	if a.GetHTMLURL() != "" {
		return a.GetHTMLURL()
	}
	return fmt.Sprintf("unknown:%d", a.GetNumber())
}

func secretScanningAlertKey(a *github.SecretScanningAlert) string {
	if a == nil {
		return ""
	}
	repo := a.GetRepository()
	if repo != nil && repo.GetID() != 0 {
		return fmt.Sprintf("%d:%d", repo.GetID(), a.GetNumber())
	}
	if a.GetHTMLURL() != "" {
		return a.GetHTMLURL()
	}
	return fmt.Sprintf("unknown:%d", a.GetNumber())
}

func extractPURLFromDependency(pkg *github.RepoDependencies) string {
	if pkg == nil {
		return ""
	}
	for _, ref := range pkg.ExternalRefs {
		if ref == nil {
			continue
		}
		if strings.EqualFold(ref.ReferenceType, "purl") || strings.EqualFold(ref.ReferenceType, "package-manager") {
			return ref.ReferenceLocator
		}
	}
	return ""
}

func ecosystemFromPURL(purl string) string {
	if !strings.HasPrefix(purl, "pkg:") {
		return ""
	}
	rest := strings.TrimPrefix(purl, "pkg:")
	if rest == "" {
		return ""
	}
	end := strings.Index(rest, "/")
	if end == -1 {
		end = strings.Index(rest, "@")
	}
	if end == -1 {
		return rest
	}
	return rest[:end]
}

func sbomCreatedAt(doc *github.SBOMInfo) string {
	if doc == nil || doc.CreationInfo == nil {
		return ""
	}
	return formatGitHubTimePtr(doc.CreationInfo.Created)
}

func sbomCreators(doc *github.SBOMInfo) string {
	if doc == nil || doc.CreationInfo == nil {
		return ""
	}
	return strings.Join(doc.CreationInfo.Creators, ",")
}

func nullableInt(v int) interface{} {
	if v == 0 {
		return nil
	}
	return v
}

func snapshotCodeScanningInstance(inst *github.MostRecentInstance) codeScanningInstanceSnapshot {
	s := codeScanningInstanceSnapshot{}
	if inst == nil {
		return s
	}
	s.ref = inst.GetRef()
	s.commitSHA = inst.GetCommitSHA()
	s.state = inst.GetState()
	s.category = inst.GetCategory()
	s.classifications = strings.Join(inst.Classifications, ",")
	if inst.Location != nil {
		s.path = inst.Location.GetPath()
		s.startLine = nullableInt(inst.Location.GetStartLine())
		s.endLine = nullableInt(inst.Location.GetEndLine())
		s.startColumn = nullableInt(inst.Location.GetStartColumn())
		s.endColumn = nullableInt(inst.Location.GetEndColumn())
	}
	return s
}

func lookupPackageIDTx(tx *sql.Tx, ecosystem, name string) (interface{}, error) {
	if safeStr(name) == "" {
		return nil, nil
	}
	var packageID int64
	err := tx.QueryRow(`
		SELECT package_id FROM packages
		WHERE ecosystem = ? AND name = ?
		LIMIT 1
	`, safeStr(ecosystem), safeStr(name)).Scan(&packageID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return packageID, nil
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func formatTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return formatTime(*t)
}

func formatGitHubTimePtr(t *github.Timestamp) string {
	if t == nil {
		return ""
	}
	return formatTime(t.Time)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func boolPtrToIntPtr(v *bool) interface{} {
	if v == nil {
		return nil
	}
	if *v {
		return 1
	}
	return 0
}

func safeStr(s string) string {
	return strings.TrimSpace(s)
}

func nullableInt64(ok bool, v int64) interface{} {
	if !ok {
		return nil
	}
	return v
}

func nullableInt64Value(v int64) interface{} {
	if v == 0 {
		return nil
	}
	return v
}

func nullableIntPtr(v *int) interface{} {
	if v == nil {
		return nil
	}
	return *v
}

func nullableString(v string) interface{} {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	return v
}

func floatPtrToValue(v *float64) interface{} {
	if v == nil {
		return nil
	}
	return *v
}

func epssPercentageValue(e *github.AdvisoryEPSS) interface{} {
	if e == nil {
		return nil
	}
	return e.Percentage
}

func epssPercentileValue(e *github.AdvisoryEPSS) interface{} {
	if e == nil {
		return nil
	}
	return e.Percentile
}

func mostRecentAnalysisKey(inst *github.MostRecentInstance) string {
	if inst == nil {
		return ""
	}
	return inst.GetAnalysisKey()
}

func repoIDKey(repoID int64) string {
	return fmt.Sprintf("id:%d", repoID)
}

func isIgnoredRepoName(name string) bool {
	return strings.EqualFold(strings.TrimSpace(name), ".github")
}

func extractImmerseCustomProperties(customProps map[string]any) (string, string, interface{}, []string) {
	if customProps == nil {
		return "", "", nil, nil
	}
	askID := toTrimmedString(customProps["immerse_ask_id"])
	jfrogProjectKey := toTrimmedString(customProps["immerse_jfrog_project_key"])
	sastCompliant := parseBoolish(customProps["immerse_sast_compliant"])
	scanners := parseStringList(customProps["immerse_sast_scanners"])
	return askID, jfrogProjectKey, sastCompliant, scanners
}

func upsertRepoScanners(db *sql.DB, repoID int64, scanners []string) error {
	if _, err := db.Exec(`DELETE FROM repo_scanners WHERE repo_id = ?`, repoID); err != nil {
		return err
	}
	if len(scanners) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(scanners))
	for _, scanner := range scanners {
		scanner = strings.TrimSpace(scanner)
		if scanner == "" {
			continue
		}
		if _, ok := seen[scanner]; ok {
			continue
		}
		seen[scanner] = struct{}{}
		if _, err := db.Exec(`
			INSERT INTO scanners(scanner)
			VALUES (?)
			ON CONFLICT(scanner) DO NOTHING
		`, scanner); err != nil {
			return err
		}
		if _, err := db.Exec(`
			INSERT INTO repo_scanners(repo_id, scanner_id)
			SELECT ?, scanner_id
			FROM scanners
			WHERE scanner = ?
			ON CONFLICT(repo_id, scanner_id) DO NOTHING
		`, repoID, scanner); err != nil {
			return err
		}
	}
	return nil
}

func toTrimmedString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(x)
	case fmt.Stringer:
		return strings.TrimSpace(x.String())
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", x))
	}
}

func parseBoolish(v any) interface{} {
	switch x := v.(type) {
	case nil:
		return nil
	case bool:
		return boolToInt(x)
	case string:
		s := strings.TrimSpace(strings.ToLower(x))
		if s == "true" {
			return 1
		}
		if s == "false" {
			return 0
		}
	case float64:
		if x == 1 {
			return 1
		}
		if x == 0 {
			return 0
		}
	case int:
		if x == 1 {
			return 1
		}
		if x == 0 {
			return 0
		}
	}
	return nil
}

func parseStringList(v any) []string {
	out := make([]string, 0)
	seen := make(map[string]struct{})
	appendVal := func(value string) {
		s := strings.TrimSpace(value)
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}

	switch x := v.(type) {
	case nil:
	case string:
		appendVal(x)
	case []string:
		for _, item := range x {
			appendVal(item)
		}
	case []interface{}:
		for _, item := range x {
			appendVal(toTrimmedString(item))
		}
	default:
		appendVal(fmt.Sprintf("%v", x))
	}
	return out
}

func stringifyDBValue(v interface{}) string {
	switch x := v.(type) {
	case nil:
		return ""
	case []byte:
		return string(x)
	case string:
		return x
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		if x {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", x)
	}
}
