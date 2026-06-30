package analysis

import (
	"regexp"
	"strings"

	"github.com/verophi/verophi/internal/version"
)

// recommendationPattern matches "Upgrade <pkg> to version <versions>"
var recommendationPattern = regexp.MustCompile(
	`(?i)(?:upgrade|update)\s+(.+?)\s+to\s+version\s+(.+)`)

// clause represents one "Upgrade <pkg> to version <tokens>" clause.
type clause struct {
	pkg    string
	tokens string
}

// parseClauses splits a recommendation into per-package clauses.
// Compound recommendations are joined by "; ".
func parseClauses(rec string) []clause {
	parts := strings.Split(rec, ";")
	var clauses []clause
	for _, part := range parts {
		part = strings.TrimSpace(part)
		m := recommendationPattern.FindStringSubmatch(part)
		if len(m) >= 3 {
			clauses = append(clauses, clause{
				pkg:    strings.TrimSpace(m[1]),
				tokens: strings.TrimSpace(m[2]),
			})
		}
	}
	return clauses
}

// candidate is a parsed fix-version candidate with its branch for supersede.
type candidate struct {
	version string
	branch  string
	isExact bool // true for >= or bare versions; false for ~>/^/~
}

// parseTokens parses the version tokens portion of a clause into candidates.
func parseTokens(tokens string) []candidate {
	parts := splitTokens(tokens)
	var cands []candidate
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, "<=") || strings.HasPrefix(p, "!=") || strings.HasPrefix(p, "<") {
			// Upper/exclusion bounds: never a fix candidate
			continue
		}
		if strings.HasPrefix(p, ">=") {
			ver := strings.TrimSpace(strings.TrimPrefix(p, ">="))
			cands = append(cands, candidate{version: ver, branch: deriveBranch(ver), isExact: true})
		} else if strings.HasPrefix(p, "~>") {
			ver := strings.TrimSpace(strings.TrimPrefix(p, "~>"))
			cands = append(cands, candidate{version: ver, branch: deriveBranchTilde(ver), isExact: false})
		} else if strings.HasPrefix(p, "^") {
			ver := strings.TrimSpace(strings.TrimPrefix(p, "^"))
			cands = append(cands, candidate{version: ver, branch: deriveBranch(ver), isExact: false})
		} else if strings.HasPrefix(p, "~") && !strings.HasPrefix(p, "~>") {
			ver := strings.TrimSpace(strings.TrimPrefix(p, "~"))
			cands = append(cands, candidate{version: ver, branch: deriveBranch(ver), isExact: false})
		} else {
			cands = append(cands, candidate{version: ver(p), branch: deriveBranch(ver(p)), isExact: true})
		}
	}
	return cands
}

func ver(s string) string { return strings.TrimSpace(s) }

// splitTokens splits on commas, respecting that versions don't contain commas.
func splitTokens(tokens string) []string {
	return strings.Split(tokens, ",")
}

// deriveBranch returns the branch for a bare or >= token.
// Uses all segments except the last (consistent with tilde/pessimistic).
func deriveBranch(v string) string {
	v = strings.TrimPrefix(v, "v")
	parts := strings.Split(v, ".")
	if len(parts) <= 1 {
		return parts[0]
	}
	// For 0.x: branch is "0.minor"
	if parts[0] == "0" && len(parts) >= 2 {
		return "0." + parts[1]
	}
	// For simple versions (2 segments like "2.15"): branch is the major
	if len(parts) == 2 {
		return parts[0]
	}
	// For 3+ segments: branch is all but the last segment
	return strings.Join(parts[:len(parts)-1], ".")
}

// deriveBranchTilde returns the branch for a ~> token.
// For Ruby gems, ~> 6.1.5 means branch "6.1".
func deriveBranchTilde(v string) string {
	v = strings.TrimPrefix(v, "v")
	parts := strings.Split(v, ".")
	if len(parts) <= 2 {
		return deriveBranch(v)
	}
	// Use all segments except the last as the branch
	return strings.Join(parts[:len(parts)-1], ".")
}

// resolveCandidates applies per-branch supersede, then selects
// comparator-minimum above affected.
func resolveCandidates(cands []candidate, affectedVersion, ecosystem string) string {
	if len(cands) == 0 {
		return ""
	}

	// Per-branch supersede: if a branch has an exact candidate, drop non-exact
	// candidates whose branch matches or is a prefix of the exact's branch.
	// This handles: ~> 6.1.5 (branch "6.1") superseded by >= 6.1.5.1 (branch "6.1.5")
	exactBranches := make([]string, 0)
	for _, c := range cands {
		if c.isExact {
			exactBranches = append(exactBranches, c.branch)
		}
	}

	var effective []string
	for _, c := range cands {
		if !c.isExact && isSuperseded(c.branch, exactBranches) {
			continue
		}
		effective = append(effective, c.version)
	}

	// Discard candidates not strictly greater than affected, select min
	comp := version.For(ecosystem)
	if comp == nil {
		// Unsupported ecosystem: borrow the semver comparator only to order the
		// recommendation candidates for the displayed fix version. Matching stays
		// honest because correlate gates on version.IsFixedBy with the real (nil)
		// comparator, which yields unknown rather than a fixed claim.
		comp = version.For("npm")
	}

	var best string
	for _, v := range effective {
		cmp, err := comp.Compare(v, affectedVersion)
		if err != nil || cmp <= 0 {
			continue
		}
		if best == "" {
			best = v
		} else {
			cmp2, err := comp.Compare(v, best)
			if err == nil && cmp2 < 0 {
				best = v
			}
		}
	}
	return best
}

// isSuperseded checks if a tilde branch is superseded by any exact branch.
// A tilde on branch "6.1" is superseded if any exact's branch starts with "6.1".
func isSuperseded(tildeBranch string, exactBranches []string) bool {
	for _, eb := range exactBranches {
		if eb == tildeBranch || strings.HasPrefix(eb, tildeBranch+".") {
			return true
		}
	}
	return false
}

// matchesIdentity checks whether a package name from a recommendation clause
// matches the occurrence identity. The comparison is exact (case-insensitive),
// never a substring: a clause "foo" must not match an occurrence "foobar" and
// bind it to the wrong clause of a compound recommendation.
func matchesIdentity(clausePkg string, occPURL, occName string) bool {
	if strings.EqualFold(clausePkg, occName) {
		return true
	}
	// Also accept the package's full PURL coordinate (namespace/name, without the
	// pkg:type prefix and version), so a recommendation that names the package by
	// its coordinate still matches exactly.
	if occPURL != "" {
		coord := extractPURLName(occPURL) // type/namespace/name
		if i := strings.IndexByte(coord, '/'); i >= 0 {
			if strings.EqualFold(clausePkg, coord[i+1:]) {
				return true
			}
		}
	}
	return false
}
