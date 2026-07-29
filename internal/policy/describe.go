package policy

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	customPolicyDescription = "Custom vulnerability policy"
	alwaysPassesDescription = "Always passes (no constraints)"
	neverPassesDescription  = "Never passes (blocks everything)"
)

var (
	whitespaceRE = regexp.MustCompile(`\s+`)

	countIdentRE = regexp.MustCompile(
		`^(criticalCount|highCount|mediumCount|lowCount|exemptedCount)\s*(==|!=|<=|>=|<|>)\s*(\d+)$`,
	)

	// vulnerabilities.filter(...).size() == 0 with optional whitespace
	filterSizeZeroRE = regexp.MustCompile(
		`(?is)^vulnerabilities\.filter\(\s*\w+\s*,\s*(.+)\s*\)\.size\(\)\s*==\s*0$`,
	)

	severityEQRE = regexp.MustCompile(
		`(?i)\bv\.severity\s*==\s*"(CRITICAL|HIGH|MEDIUM|LOW)"`,
	)
	fixedVersionNonEmptyRE = regexp.MustCompile(`(?i)\bv\.fixedVersion\s*!=\s*""`)
	fixedVersionEmptyRE    = regexp.MustCompile(`(?i)\bv\.fixedVersion\s*==\s*""`)
	notExemptedRE          = regexp.MustCompile(`(?i)!?\bv\.exempted\b`)
	packageStartsWithRE    = regexp.MustCompile(`(?i)\bv\.packageName\.startsWith\(\s*"([^"]+)"\s*\)`)
	cveAllowlistRE         = regexp.MustCompile(`(?is)!\(\s*v\.id\s+in\s+\[([^\]]+)\]\s*\)`)
	cveIDRE                = regexp.MustCompile(`"(CVE-[^"]+)"`)
)

var countLabels = map[string]string{
	"criticalCount": "critical",
	"highCount":     "high",
	"mediumCount":   "medium",
	"lowCount":      "low",
	"exemptedCount": "exempted",
}

// DescribeExpression turns a CEL policy expression into a short English summary.
// Unrecognized expressions return "Custom vulnerability policy".
func DescribeExpression(expr string) string {
	normalized := normalizeCEL(expr)
	if normalized == "" {
		return customPolicyDescription
	}

	if desc, ok := describeBooleanExpr(normalized); ok {
		return desc
	}
	return customPolicyDescription
}

func normalizeCEL(expr string) string {
	s := strings.TrimSpace(expr)
	if s == "" {
		return ""
	}
	return whitespaceRE.ReplaceAllString(s, " ")
}

// describeBooleanExpr handles a top-level expression that may be AND/OR of clauses.
func describeBooleanExpr(expr string) (string, bool) {
	if value, ok := boolLiteral(expr); ok {
		return literalDescription(value), true
	}

	orParts := splitTopLevel(expr, "||")
	if len(orParts) > 1 {
		descs := make([]string, 0, len(orParts))
		for _, part := range orParts {
			// A literal true short-circuits the disjunction; a literal false drops out.
			if value, ok := boolLiteral(part); ok {
				if value {
					return alwaysPassesDescription, true
				}
				continue
			}
			d, ok := describeBooleanExpr(strings.TrimSpace(part))
			if !ok {
				return "", false
			}
			descs = append(descs, d)
		}
		switch len(descs) {
		case 0:
			return neverPassesDescription, true
		case 1:
			return descs[0], true
		default:
			return strings.Join(descs, " or "), true
		}
	}

	andParts := splitTopLevel(expr, "&&")
	if len(andParts) > 1 {
		kept := make([]string, 0, len(andParts))
		for _, part := range andParts {
			// A literal false short-circuits the conjunction; a literal true drops out.
			if value, ok := boolLiteral(part); ok {
				if !value {
					return neverPassesDescription, true
				}
				continue
			}
			kept = append(kept, part)
		}
		switch len(kept) {
		case 0:
			return alwaysPassesDescription, true
		case 1:
			return describeAtom(strings.TrimSpace(kept[0]))
		default:
			return describeAndClauses(kept)
		}
	}

	return describeAtom(expr)
}

// boolLiteral reports whether expr is the literal true or false, ignoring wrapping parentheses.
func boolLiteral(expr string) (value bool, ok bool) {
	s := strings.TrimSpace(expr)
	for strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") && balancedOuterParens(s) {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	switch s {
	case "true":
		return true, true
	case "false":
		return false, true
	default:
		return false, false
	}
}

func literalDescription(value bool) string {
	if value {
		return alwaysPassesDescription
	}
	return neverPassesDescription
}

func describeAndClauses(parts []string) (string, bool) {
	zeroSeverities := make([]string, 0)
	otherDescs := make([]string, 0)

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if label, op, n, ok := parseCountAtom(part); ok && op == "==" && n == 0 {
			zeroSeverities = append(zeroSeverities, label)
			continue
		}
		d, ok := describeAtom(part)
		if !ok {
			return "", false
		}
		otherDescs = append(otherDescs, d)
	}

	clauses := make([]string, 0, 1+len(otherDescs))
	if len(zeroSeverities) > 0 {
		clauses = append(clauses, formatNoSeverities(zeroSeverities))
	}
	clauses = append(clauses, otherDescs...)
	return joinAnd(clauses), true
}

func describeAtom(expr string) (string, bool) {
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") && balancedOuterParens(expr) {
		return describeBooleanExpr(strings.TrimSpace(expr[1 : len(expr)-1]))
	}

	if label, op, n, ok := parseCountAtom(expr); ok {
		return formatCountClause(label, op, n), true
	}

	if desc, ok := describeFilterAtom(expr); ok {
		return desc, true
	}

	return "", false
}

func parseCountAtom(expr string) (label, op string, n int, ok bool) {
	m := countIdentRE.FindStringSubmatch(strings.TrimSpace(expr))
	if m == nil {
		return "", "", 0, false
	}
	label = countLabels[m[1]]
	op = m[2]
	n, err := strconv.Atoi(m[3])
	if err != nil {
		return "", "", 0, false
	}
	return label, op, n, true
}

func formatCountClause(label, op string, n int) string {
	noun := label + " vulnerabilities"
	switch op {
	case "==":
		if n == 0 {
			return "No " + noun
		}
		return fmt.Sprintf("Exactly %d %s", n, noun)
	case "!=":
		return fmt.Sprintf("Not exactly %d %s", n, noun)
	case "<=":
		if n == 0 {
			return "No " + noun
		}
		return fmt.Sprintf("At most %d %s", n, noun)
	case "<":
		if n <= 1 {
			return "No " + noun
		}
		return fmt.Sprintf("Fewer than %d %s", n, noun)
	case ">=":
		return fmt.Sprintf("At least %d %s", n, noun)
	case ">":
		return fmt.Sprintf("More than %d %s", n, noun)
	default:
		return customPolicyDescription
	}
}

func formatNoSeverities(labels []string) string {
	if len(labels) == 1 {
		return "No " + labels[0] + " vulnerabilities"
	}
	if len(labels) == 2 {
		return "No " + labels[0] + " or " + labels[1] + " vulnerabilities"
	}
	// "No critical, high, or medium vulnerabilities"
	head := strings.Join(labels[:len(labels)-1], ", ")
	return "No " + head + ", or " + labels[len(labels)-1] + " vulnerabilities"
}

func joinAnd(parts []string) string {
	switch len(parts) {
	case 0:
		return customPolicyDescription
	case 1:
		return parts[0]
	case 2:
		return parts[0] + " and " + softenClause(parts[1])
	default:
		out := parts[0]
		for i := 1; i < len(parts)-1; i++ {
			out += ", " + softenClause(parts[i])
		}
		return out + ", and " + softenClause(parts[len(parts)-1])
	}
}

// softenClause lowercases the lead-in and shortens count clauses for use after "and".
func softenClause(s string) string {
	prefixes := []string{"At most ", "Fewer than ", "At least ", "More than ", "Exactly ", "Not exactly ", "No "}
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			rest := strings.TrimPrefix(s, p)
			if p != "No " {
				rest = strings.TrimSuffix(rest, " vulnerabilities")
			}
			return strings.ToLower(p) + rest
		}
	}
	return s
}

func describeFilterAtom(expr string) (string, bool) {
	m := filterSizeZeroRE.FindStringSubmatch(expr)
	if m == nil {
		return "", false
	}
	body := whitespaceRE.ReplaceAllString(strings.TrimSpace(m[1]), " ")

	sevMatch := severityEQRE.FindStringSubmatch(body)
	if sevMatch == nil {
		return "", false
	}
	severity := strings.ToLower(sevMatch[1])

	hasFixedNonEmpty := fixedVersionNonEmptyRE.MatchString(body)
	hasFixedEmpty := fixedVersionEmptyRE.MatchString(body)
	pkgMatch := packageStartsWithRE.FindStringSubmatch(body)
	cveMatch := cveAllowlistRE.FindStringSubmatch(body)

	// Strip known conjuncts and see if anything meaningful remains unrecognized.
	residual := body
	residual = severityEQRE.ReplaceAllString(residual, "")
	residual = fixedVersionNonEmptyRE.ReplaceAllString(residual, "")
	residual = fixedVersionEmptyRE.ReplaceAllString(residual, "")
	residual = packageStartsWithRE.ReplaceAllString(residual, "")
	residual = cveAllowlistRE.ReplaceAllString(residual, "")
	residual = notExemptedRE.ReplaceAllString(residual, "")
	residual = strings.ReplaceAll(residual, "&&", "")
	residual = strings.TrimSpace(residual)
	residual = strings.Trim(residual, "()")
	residual = strings.TrimSpace(residual)
	if residual != "" && residual != "!" {
		// leftover tokens we don't understand
		if !regexp.MustCompile(`^[\s!&|()]*$`).MatchString(residual) {
			return "", false
		}
	}

	switch {
	case pkgMatch != nil && !hasFixedNonEmpty && !hasFixedEmpty && cveMatch == nil:
		return fmt.Sprintf("No %s vulnerabilities in packages starting with %q", severity, pkgMatch[1]), true
	case hasFixedNonEmpty && !hasFixedEmpty && pkgMatch == nil && cveMatch == nil:
		return fmt.Sprintf("No fixable %s vulnerabilities", severity), true
	case hasFixedEmpty && !hasFixedNonEmpty && pkgMatch == nil && cveMatch == nil:
		return fmt.Sprintf("No unfixable %s vulnerabilities", severity), true
	case cveMatch != nil && !hasFixedNonEmpty && !hasFixedEmpty && pkgMatch == nil:
		ids := cveIDRE.FindAllStringSubmatch(cveMatch[1], -1)
		if len(ids) == 0 {
			return fmt.Sprintf("No %s vulnerabilities (with CVE exceptions)", severity), true
		}
		names := make([]string, 0, len(ids))
		for _, id := range ids {
			names = append(names, id[1])
		}
		return fmt.Sprintf("No %s vulnerabilities (excluding %s)", severity, strings.Join(names, ", ")), true
	case !hasFixedNonEmpty && !hasFixedEmpty && pkgMatch == nil && cveMatch == nil:
		return fmt.Sprintf("No %s vulnerabilities", severity), true
	default:
		return "", false
	}
}

// splitTopLevel splits expr on sep only when not inside parentheses or strings.
func splitTopLevel(expr, sep string) []string {
	parts := make([]string, 0, 2)
	depth := 0
	inString := false
	start := 0
	for i := 0; i < len(expr); {
		c := expr[i]
		if inString {
			if c == '\\' && i+1 < len(expr) {
				i += 2
				continue
			}
			if c == '"' {
				inString = false
			}
			i++
			continue
		}
		switch c {
		case '"':
			inString = true
			i++
		case '(':
			depth++
			i++
		case ')':
			depth--
			i++
		default:
			if depth == 0 && strings.HasPrefix(expr[i:], sep) {
				parts = append(parts, strings.TrimSpace(expr[start:i]))
				i += len(sep)
				start = i
				continue
			}
			i++
		}
	}
	parts = append(parts, strings.TrimSpace(expr[start:]))
	return parts
}

func balancedOuterParens(expr string) bool {
	if len(expr) < 2 || expr[0] != '(' || expr[len(expr)-1] != ')' {
		return false
	}
	depth := 0
	inString := false
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		if inString {
			if c == '\\' && i+1 < len(expr) {
				i++
				continue
			}
			if c == '"' {
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 && i != len(expr)-1 {
				return false
			}
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0
}
