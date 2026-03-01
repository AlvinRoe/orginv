package sqlite

import (
	"strconv"
	"strings"
	"unicode"
)

type versionConstraint struct {
	op      string
	version string
}

func vulnerableRangeMatches(version, vulnerableRange string) bool {
	version = normalizeVersion(version)
	vulnerableRange = strings.TrimSpace(vulnerableRange)
	if version == "" || vulnerableRange == "" {
		return false
	}

	for _, clause := range splitRangeAlternatives(vulnerableRange) {
		constraints := parseVersionConstraints(clause)
		if len(constraints) == 0 {
			continue
		}
		if satisfiesAllConstraints(version, constraints) {
			return true
		}
	}
	return false
}

func splitRangeAlternatives(v string) []string {
	parts := strings.Split(v, "||")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	if len(out) == 0 {
		return []string{v}
	}
	return out
}

func parseVersionConstraints(v string) []versionConstraint {
	parts := strings.Split(v, ",")
	constraints := make([]versionConstraint, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		op := ""
		switch {
		case strings.HasPrefix(part, ">="):
			op = ">="
			part = strings.TrimSpace(strings.TrimPrefix(part, ">="))
		case strings.HasPrefix(part, "<="):
			op = "<="
			part = strings.TrimSpace(strings.TrimPrefix(part, "<="))
		case strings.HasPrefix(part, ">"):
			op = ">"
			part = strings.TrimSpace(strings.TrimPrefix(part, ">"))
		case strings.HasPrefix(part, "<"):
			op = "<"
			part = strings.TrimSpace(strings.TrimPrefix(part, "<"))
		case strings.HasPrefix(part, "=="):
			op = "="
			part = strings.TrimSpace(strings.TrimPrefix(part, "=="))
		case strings.HasPrefix(part, "="):
			op = "="
			part = strings.TrimSpace(strings.TrimPrefix(part, "="))
		default:
			op = "="
		}
		part = normalizeVersion(part)
		if part == "" {
			continue
		}
		constraints = append(constraints, versionConstraint{op: op, version: part})
	}
	return constraints
}

func satisfiesAllConstraints(version string, constraints []versionConstraint) bool {
	for _, constraint := range constraints {
		cmp := compareVersions(version, constraint.version)
		switch constraint.op {
		case "=":
			if cmp != 0 {
				return false
			}
		case "<":
			if cmp >= 0 {
				return false
			}
		case "<=":
			if cmp > 0 {
				return false
			}
		case ">":
			if cmp <= 0 {
				return false
			}
		case ">=":
			if cmp < 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func compareVersions(left, right string) int {
	leftParts := splitVersionParts(normalizeVersion(left))
	rightParts := splitVersionParts(normalizeVersion(right))
	maxLen := len(leftParts)
	if len(rightParts) > maxLen {
		maxLen = len(rightParts)
	}
	for i := 0; i < maxLen; i++ {
		var leftPart, rightPart string
		if i < len(leftParts) {
			leftPart = leftParts[i]
		}
		if i < len(rightParts) {
			rightPart = rightParts[i]
		}
		if leftPart == rightPart {
			continue
		}
		if cmp, ok := compareVersionPart(leftPart, rightPart); ok && cmp != 0 {
			return cmp
		}
		if leftPart < rightPart {
			return -1
		}
		if leftPart > rightPart {
			return 1
		}
	}
	return 0
}

func compareVersionPart(left, right string) (int, bool) {
	leftNum, leftOK := strconv.Atoi(left)
	rightNum, rightOK := strconv.Atoi(right)
	if leftOK == nil && rightOK == nil {
		switch {
		case leftNum < rightNum:
			return -1, true
		case leftNum > rightNum:
			return 1, true
		default:
			return 0, true
		}
	}
	return 0, false
}

func splitVersionParts(v string) []string {
	fields := strings.FieldsFunc(v, func(r rune) bool {
		return r == '.' || r == '-' || r == '+' || r == '_' || unicode.IsSpace(r)
	})
	if len(fields) == 0 {
		return []string{""}
	}
	return fields
}

func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	return strings.ToLower(v)
}
