package analysis

import (
	"strings"

	"github.com/verophi/verophi/internal/normalize"
	"github.com/verophi/verophi/internal/version"
	"github.com/verophi/verophi/pkg/model"
)

// correlate runs occurrence-level matching between advisories and change requests.
// It modifies the change requests in place, adding AdvisoryMatches.
func correlate(advisories []model.Advisory, requests []model.ChangeRequest) {
	for ai := range advisories {
		adv := &advisories[ai]
		for oi := range adv.Occurrences {
			occ := &adv.Occurrences[oi]
			fixVersion := deriveFixVersion(adv.Recommendation, occ)
			if fixVersion == "" {
				continue
			}
			occ.FixVersion = fixVersion

			for ri := range requests {
				r := &requests[ri]
				for ai2 := range r.Assessments {
					a := &r.Assessments[ai2]
					if !identityMatch(a.Change, *occ) {
						continue
					}
					result := version.IsFixedBy(occ.Ecosystem, a.Change.TargetVersion, fixVersion)
					if result == version.Fixed {
						matchedOcc := *occ
						matchedOcc.Addressed = true
						match := model.AdvisoryMatch{
							Advisory: model.AdvisoryRef{
								ID:       adv.ID,
								Aliases:  adv.Aliases,
								Severity: adv.Severity,
								CVSS:     adv.CVSS,
							},
							Occurrence: matchedOcc,
							Confidence: confidenceFor(result),
						}
						a.AdvisoryMatches = append(a.AdvisoryMatches, match)
					}
				}
			}
		}
	}

	// Set status: matched if any advisory match exists
	for ri := range requests {
		r := &requests[ri]
		if r.Status == model.StatusParsed {
			if hasAnyMatch(r) {
				r.Status = model.StatusMatched
			} else {
				r.Status = model.StatusUnmatched
			}
		}
	}
}

// deriveFixVersion determines the fix version for an occurrence from the
// advisory recommendation using the token rules and min-above-affected selection.
func deriveFixVersion(recommendation string, occ *model.Occurrence) string {
	if recommendation == "" {
		return ""
	}

	clauses := parseClauses(recommendation)
	if len(clauses) == 0 {
		return ""
	}

	// For compound recommendations, find the clause matching this occurrence
	var tokens string
	if len(clauses) == 1 {
		tokens = clauses[0].tokens
	} else {
		for _, cl := range clauses {
			if matchesIdentity(cl.pkg, occ.PURL, occ.DependencyName) {
				tokens = cl.tokens
				break
			}
		}
		if tokens == "" {
			return ""
		}
	}

	cands := parseTokens(tokens)
	return resolveCandidates(cands, occ.AffectedVersion, occ.Ecosystem)
}

// identityMatch checks if a change addresses the same dependency as an occurrence.
func identityMatch(change model.Change, occ model.Occurrence) bool {
	// Changes parsed from the Renovate table carry no PURL. When the occurrence
	// has one, match the change name against the PURL coordinate. This recovers
	// Maven group:artifact names, whose occurrence carries only the artifactId as
	// its name but the full groupId in its PURL, so the groupId is still
	// respected.
	if occ.PURL != "" && nameMatchesPURLCoordinate(change.DependencyName, occ.PURL) {
		return true
	}
	// Maven identity must come from the groupId-aware PURL coordinate above. The
	// bare-artifactId fallback below would match across groupIds (e.g. a
	// different group's log4j-core), so it is not safe for Maven; treat a Maven
	// occurrence that did not match by coordinate as unmatched.
	if occ.Ecosystem == "maven" {
		return false
	}
	// Fallback: ecosystem-aware name normalization (occurrence ecosystem drives it).
	return normalize.DependencyName(change.DependencyName, occ.Ecosystem) == normalize.DependencyName(occ.DependencyName, occ.Ecosystem)
}

// nameMatchesPURLCoordinate matches a title-parsed change name (which carries no
// PURL) against the type/namespace/name of an occurrence PURL. Two ecosystem
// conventions need reconciling:
//   - Maven: the change name is a group:artifact coordinate while the occurrence
//     name is only the artifactId; comparing the full group/artifact against the
//     PURL namespace keeps the groupId disambiguating.
//   - Swift: Renovate names the package by its repository shorthand
//     (apple/swift-nio-http2) while the SBOM uses the full module path
//     (github.com/apple/swift-nio-http2); stripping the VCS host from the PURL
//     coordinate reconciles them.
func nameMatchesPURLCoordinate(name, purl string) bool {
	coord := extractPURLName(purl) // e.g. "maven/org.apache.logging.log4j/log4j-core"
	segs := strings.SplitN(coord, "/", 2)
	if len(segs) != 2 {
		return false
	}
	ptype, nsName := segs[0], segs[1]
	switch ptype {
	case "maven":
		if i := strings.LastIndex(name, ":"); i >= 0 {
			want := name[:i] + "/" + name[i+1:]
			return strings.EqualFold(want, nsName)
		}
	case "swift":
		return strings.EqualFold(name, stripVCSHost(nsName))
	}
	return false
}

// stripVCSHost removes a leading VCS host segment (github.com/, gitlab.com/,
// bitbucket.org/) from a module path so a repository shorthand matches the full
// path.
func stripVCSHost(path string) string {
	for _, host := range []string{"github.com/", "gitlab.com/", "bitbucket.org/"} {
		if strings.HasPrefix(path, host) {
			return path[len(host):]
		}
	}
	return path
}

// extractPURLName extracts the type/namespace/name from a PURL, ignoring the version.
func extractPURLName(purl string) string {
	// pkg:type/namespace/name@version -> type/namespace/name
	s := purl
	if idx := indexByte(s, '@'); idx >= 0 {
		s = s[:idx]
	}
	if idx := indexByte(s, '?'); idx >= 0 {
		s = s[:idx]
	}
	if len(s) > 4 && s[:4] == "pkg:" {
		s = s[4:]
	}
	return s
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func hasAnyMatch(cr *model.ChangeRequest) bool {
	for _, a := range cr.Assessments {
		if len(a.AdvisoryMatches) > 0 {
			return true
		}
	}
	return false
}

func confidenceFor(r version.Result) model.Confidence {
	switch r {
	case version.Fixed:
		return model.ConfidenceHigh
	default:
		return model.ConfidenceLower
	}
}
