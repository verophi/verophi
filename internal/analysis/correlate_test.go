package analysis

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/verophi/verophi/internal/version"
	"github.com/verophi/verophi/pkg/model"
)

func TestDeriveFixVersion_SingleBare(t *testing.T) {
	occ := &model.Occurrence{
		DependencyName: "lodash", Ecosystem: "npm", AffectedVersion: "4.17.20",
		PURL: "pkg:npm/lodash@4.17.20",
	}
	fix := deriveFixVersion("Upgrade lodash to version 4.17.21", occ)
	assert.Equal(t, "4.17.21", fix)
}

func TestDeriveFixVersion_CrossBranchMin_Axios(t *testing.T) {
	// axios 0.21.1, recommendation "1.15.1, 0.31.1"
	// Neither is on branch 0.21; min above 0.21.1 = 0.31.1
	occ := &model.Occurrence{
		DependencyName: "axios", Ecosystem: "npm", AffectedVersion: "0.21.1",
		PURL: "pkg:npm/axios@0.21.1",
	}
	fix := deriveFixVersion("Upgrade axios to version 1.15.1, 0.31.1", occ)
	assert.Equal(t, "0.31.1", fix)
}

func TestDeriveFixVersion_Log4j_MinAboveAffected(t *testing.T) {
	// log4j 2.14.1, recommendation "2.15.0, 2.3.1, 2.12.2"
	// All on branch 2; discard 2.3.1 and 2.12.2 (< 2.14.1); min above = 2.15.0
	occ := &model.Occurrence{
		DependencyName: "org.apache.logging.log4j:log4j-core", Ecosystem: "maven",
		AffectedVersion: "2.14.1",
		PURL:            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
	}
	fix := deriveFixVersion("Upgrade org.apache.logging.log4j:log4j-core to version 2.15.0, 2.3.1, 2.12.2", occ)
	assert.Equal(t, "2.15.0", fix)
}

func TestDeriveFixVersion_Qs_MinAboveAffected(t *testing.T) {
	// qs 6.7.0, recommendation "6.10.3, 6.9.7, 6.8.3, 6.7.3, 6.6.1, 6.5.3, 6.4.1, 6.3.3, 6.2.4"
	// Discard all <= 6.7.0; min above = 6.7.3
	occ := &model.Occurrence{
		DependencyName: "qs", Ecosystem: "npm", AffectedVersion: "6.7.0",
		PURL: "pkg:npm/qs@6.7.0",
	}
	fix := deriveFixVersion("Upgrade qs to version 6.10.3, 6.9.7, 6.8.3, 6.7.3, 6.6.1, 6.5.3, 6.4.1, 6.3.3, 6.2.4", occ)
	assert.Equal(t, "6.7.3", fix)
}

func TestDeriveFixVersion_Tokio_MinAboveAffected(t *testing.T) {
	// tokio 1.17.0, recommendation "1.18.4, 1.20.3, 1.23.1"
	// All > 1.17.0; min = 1.18.4
	occ := &model.Occurrence{
		DependencyName: "tokio", Ecosystem: "cargo", AffectedVersion: "1.17.0",
		PURL: "pkg:cargo/tokio@1.17.0",
	}
	fix := deriveFixVersion("Upgrade tokio to version 1.18.4, 1.20.3, 1.23.1", occ)
	assert.Equal(t, "1.18.4", fix)
}

func TestDeriveFixVersion_Nokogiri_CrossBranch(t *testing.T) {
	// nokogiri 1.13.10, recommendation "~> 1.15.6, >= 1.16.2"
	// branch 1.15 has lone ~> 1.15.6; branch 1.16 has >= 1.16.2
	// Both > 1.13.10; min = 1.15.6
	occ := &model.Occurrence{
		DependencyName: "nokogiri", Ecosystem: "gem", AffectedVersion: "1.13.10",
		PURL: "pkg:gem/nokogiri@1.13.10",
	}
	fix := deriveFixVersion("Upgrade nokogiri to version ~> 1.15.6, >= 1.16.2", occ)
	assert.Equal(t, "1.15.6", fix)
}

func TestDeriveFixVersion_Actionpack_Supersede(t *testing.T) {
	// actionpack 6.1.4, recommendation "~> 5.2.7, >= 5.2.7.1, ~> 6.0.4, >= 6.0.4.8, ~> 6.1.5, >= 6.1.5.1, >= 7.0.2.4"
	// branch 6.1: ~> 6.1.5 superseded by >= 6.1.5.1 (same branch)
	// Candidates after supersede: 5.2.7.1, 6.0.4.8, 6.1.5.1, 7.0.2.4
	// Discard <= 6.1.4: {6.1.5.1, 7.0.2.4}; min = 6.1.5.1
	occ := &model.Occurrence{
		DependencyName: "actionpack", Ecosystem: "gem", AffectedVersion: "6.1.4",
		PURL: "pkg:gem/actionpack@6.1.4",
	}
	fix := deriveFixVersion("Upgrade actionpack to version ~> 5.2.7, >= 5.2.7.1, ~> 6.0.4, >= 6.0.4.8, ~> 6.1.5, >= 6.1.5.1, >= 7.0.2.4", occ)
	assert.Equal(t, "6.1.5.1", fix)
}

func TestDeriveFixVersion_GoVPrefix_Gin(t *testing.T) {
	// gin v1.7.0, recommendation "1.7.7"
	// Go canonicalization: compare v1.7.0 vs 1.7.7 -> 1.7.7 > 1.7.0 -> fix = 1.7.7
	occ := &model.Occurrence{
		DependencyName: "github.com/gin-gonic/gin", Ecosystem: "go",
		AffectedVersion: "v1.7.0",
		PURL:            "pkg:golang/github.com/gin-gonic/gin@v1.7.0",
	}
	fix := deriveFixVersion("Upgrade github.com/gin-gonic/gin to version 1.7.7", occ)
	assert.Equal(t, "1.7.7", fix)
}

func TestDeriveFixVersion_Compound_CVE2023_44487(t *testing.T) {
	// CVE-2023-44487: "Upgrade github.com/apple/swift-nio-http2 to version 1.28.0; Upgrade golang.org/x/net to version 0.17.0"
	occ1 := &model.Occurrence{
		DependencyName: "github.com/apple/swift-nio-http2", Ecosystem: "swift",
		AffectedVersion: "1.25.0",
		PURL:            "pkg:swift/github.com/apple/swift-nio-http2@1.25.0",
	}
	rec := "Upgrade github.com/apple/swift-nio-http2 to version 1.28.0; Upgrade golang.org/x/net to version 0.17.0"
	fix1 := deriveFixVersion(rec, occ1)
	assert.Equal(t, "1.28.0", fix1)

	occ2 := &model.Occurrence{
		DependencyName: "golang.org/x/net", Ecosystem: "go",
		AffectedVersion: "v0.16.0",
		PURL:            "pkg:golang/golang.org/x/net@v0.16.0",
	}
	fix2 := deriveFixVersion(rec, occ2)
	assert.Equal(t, "0.17.0", fix2)
}

func TestCorrelate_SetsMatchedStatus(t *testing.T) {
	advisories := []model.Advisory{
		{
			ID: "CVE-TEST-1", Severity: model.SeverityHigh,
			Recommendation: "Upgrade lodash to version 4.17.21",
			Occurrences: []model.Occurrence{
				{BOMRef: "pkg:npm/lodash@4.17.20", PURL: "pkg:npm/lodash@4.17.20",
					DependencyName: "lodash", Ecosystem: "npm", AffectedVersion: "4.17.20"},
			},
		},
	}
	requests := []model.ChangeRequest{
		{
			Number: 1, Status: model.StatusParsed,
			Assessments: []model.ChangeAssessment{
				{Change: model.Change{
					DependencyName: "lodash", TargetVersion: "4.17.21",
					ChangeType: model.ChangePatch,
				}},
			},
		},
	}

	correlate(advisories, requests)

	assert.Equal(t, model.StatusMatched, requests[0].Status)
	assert.Len(t, requests[0].Assessments[0].AdvisoryMatches, 1)
	assert.Equal(t, "CVE-TEST-1", requests[0].Assessments[0].AdvisoryMatches[0].Advisory.ID)
}

// TestIdentityMatch_MavenCoordinateVsArtifactID guards the Maven identity
// recovery. A title-parsed change carries no PURL and the full group:artifact
// coordinate, while the SBOM occurrence carries only the artifactId as its name
// but the full groupId in its PURL. They must match, and a different groupId
// with the same artifactId must NOT match (R14.1).
func TestIdentityMatch_MavenCoordinateVsArtifactID(t *testing.T) {
	occ := model.Occurrence{
		DependencyName:  "log4j-core",
		Ecosystem:       "maven",
		PURL:            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
		AffectedVersion: "2.14.1",
	}

	// Title-parsed change: no PURL, no ecosystem, name is group:artifact.
	matching := model.Change{
		DependencyName: "org.apache.logging.log4j:log4j-core",
		TargetVersion:  "2.17.1",
	}
	assert.True(t, identityMatch(matching, occ),
		"group:artifact change must match an occurrence whose name is the artifactId with the full groupId in its PURL")

	// Same artifactId, different groupId: must not match (groupId disambiguates).
	differentGroup := model.Change{
		DependencyName: "com.example:log4j-core",
		TargetVersion:  "2.17.1",
	}
	assert.False(t, identityMatch(differentGroup, occ),
		"a different groupId with the same artifactId must not match (R14.1)")
}

// TestCorrelate_MavenGroupArtifact_TitleParsed is the end-to-end guard: a
// title-parsed Maven change (no PURL) must correlate to the advisory whose
// occurrence carries only the artifactId.
func TestCorrelate_MavenGroupArtifact_TitleParsed(t *testing.T) {
	advisories := []model.Advisory{
		{
			ID: "CVE-2021-44228", Severity: model.SeverityCritical,
			Recommendation: "Upgrade org.apache.logging.log4j:log4j-core to version 2.15.0",
			Occurrences: []model.Occurrence{
				{
					BOMRef:          "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
					PURL:            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
					DependencyName:  "log4j-core",
					Ecosystem:       "maven",
					AffectedVersion: "2.14.1",
				},
			},
		},
	}
	requests := []model.ChangeRequest{
		{
			Number: 81, Status: model.StatusParsed,
			Assessments: []model.ChangeAssessment{
				{Change: model.Change{
					DependencyName: "org.apache.logging.log4j:log4j-core",
					TargetVersion:  "2.17.1",
					ChangeType:     model.ChangeMinor,
				}},
			},
		},
	}

	correlate(advisories, requests)

	assert.Equal(t, model.StatusMatched, requests[0].Status)
	assert.Len(t, requests[0].Assessments[0].AdvisoryMatches, 1)
}

// TestIdentityMatch_SwiftRepoShorthand guards the Swift case where Renovate
// names the package by its repository shorthand (apple/swift-nio-http2) while
// the SBOM occurrence carries the full module path and PURL
// (github.com/apple/swift-nio-http2). They must match; a different org must not.
func TestIdentityMatch_SwiftRepoShorthand(t *testing.T) {
	occ := model.Occurrence{
		DependencyName:  "github.com/apple/swift-nio-http2",
		Ecosystem:       "swift",
		PURL:            "pkg:swift/github.com/apple/swift-nio-http2@1.25.0",
		AffectedVersion: "1.25.0",
	}
	match := model.Change{DependencyName: "apple/swift-nio-http2", TargetVersion: "1.28.0"}
	assert.True(t, identityMatch(match, occ),
		"Renovate repo shorthand must match the full SBOM module path via the swift PURL")

	other := model.Change{DependencyName: "other-org/swift-nio-http2", TargetVersion: "1.28.0"}
	assert.False(t, identityMatch(other, occ),
		"a different org must not match")
}

// TestCorrelate_SwiftCompound_CVE2023_44487 is the end-to-end guard: a Swift
// change named with the repository shorthand must correlate to its occurrence in
// the compound CVE-2023-44487 recommendation, using the real fixture names.
func TestCorrelate_SwiftCompound_CVE2023_44487(t *testing.T) {
	rec := "Upgrade github.com/apple/swift-nio-http2 to version 1.28.0; Upgrade golang.org/x/net to version 0.17.0"
	advisories := []model.Advisory{{
		ID: "CVE-2023-44487", Severity: model.SeverityHigh, Recommendation: rec,
		Occurrences: []model.Occurrence{
			{
				BOMRef:         "pkg:swift/github.com/apple/swift-nio-http2@1.25.0",
				PURL:           "pkg:swift/github.com/apple/swift-nio-http2@1.25.0",
				DependencyName: "github.com/apple/swift-nio-http2", Ecosystem: "swift", AffectedVersion: "1.25.0",
			},
			{
				BOMRef:         "pkg:golang/golang.org/x/net@v0.16.0",
				PURL:           "pkg:golang/golang.org/x/net@v0.16.0",
				DependencyName: "golang.org/x/net", Ecosystem: "go", AffectedVersion: "v0.16.0",
			},
		},
	}}
	requests := []model.ChangeRequest{{
		Number: 71, Status: model.StatusParsed,
		Assessments: []model.ChangeAssessment{
			{Change: model.Change{DependencyName: "apple/swift-nio-http2", TargetVersion: "1.28.0", ChangeType: model.ChangeMinor}},
		},
	}}

	correlate(advisories, requests)

	assert.Equal(t, model.StatusMatched, requests[0].Status, "swift request must be matched")
	assert.Len(t, requests[0].Assessments[0].AdvisoryMatches, 1)
	assert.Equal(t, "CVE-2023-44487", requests[0].Assessments[0].AdvisoryMatches[0].Advisory.ID)
}

// TestIdentityMatch_EcosystemAwareNameFallback guards that the name fallback
// uses ecosystem-aware normalization (internal/normalize), not a blanket rule.
// Python PEP 503: name is case-insensitive and runs of [-_.] are equivalent, so
// a Renovate "Pillow" matches an SBOM "pillow" and "ruamel.yaml" matches
// "ruamel-yaml". The occurrence's ecosystem drives normalization.
func TestIdentityMatch_EcosystemAwareNameFallback(t *testing.T) {
	occ := model.Occurrence{DependencyName: "pillow", Ecosystem: "pip", AffectedVersion: "9.0.0"}
	change := model.Change{DependencyName: "Pillow", TargetVersion: "10.2.0"}
	assert.True(t, identityMatch(change, occ), "PEP 503 case-insensitive match")

	occ2 := model.Occurrence{DependencyName: "ruamel-yaml", Ecosystem: "pip", AffectedVersion: "0.17.0"}
	change2 := model.Change{DependencyName: "ruamel.yaml", TargetVersion: "0.18.0"}
	assert.True(t, identityMatch(change2, occ2), "PEP 503 separator equivalence")
}

func TestParseTokens_OperatorRules(t *testing.T) {
	// <, <=, != are bounds and never contribute; >= and bare are exact;
	// ~>, ^, ~ are non-exact (branch markers).
	cands := parseTokens("< 1.0, <= 2.0, != 3.0, >= 4.0, ~> 5.0, ^6.0, ~7.0, 8.0")
	got := map[string]bool{}
	exact := map[string]bool{}
	for _, c := range cands {
		got[c.version] = true
		exact[c.version] = c.isExact
	}
	assert.False(t, got["1.0"], "< dropped")
	assert.False(t, got["2.0"], "<= dropped")
	assert.False(t, got["3.0"], "!= dropped")
	assert.True(t, got["4.0"] && exact["4.0"], ">= is exact candidate")
	assert.True(t, got["5.0"] && !exact["5.0"], "~> is non-exact")
	assert.True(t, got["6.0"] && !exact["6.0"], "^ is non-exact")
	assert.True(t, got["7.0"] && !exact["7.0"], "~ is non-exact")
	assert.True(t, got["8.0"] && exact["8.0"], "bare is exact")
}

func TestDeriveBranch(t *testing.T) {
	assert.Equal(t, "6.1", deriveBranch("6.1.4"))
	assert.Equal(t, "0.31", deriveBranch("0.31.1"))
	assert.Equal(t, "2", deriveBranch("2.15"))
	assert.Equal(t, "1", deriveBranch("1"))
	assert.Equal(t, "1.7", deriveBranch("v1.7.0"))
}

func TestDeriveBranchTilde(t *testing.T) {
	assert.Equal(t, "6.1", deriveBranchTilde("6.1.5"))
	assert.Equal(t, "5.2", deriveBranchTilde("5.2.7"))
	assert.Equal(t, "1", deriveBranchTilde("1.2"))
}

func TestResolveCandidates_EdgeCases(t *testing.T) {
	assert.Equal(t, "", resolveCandidates(nil, "1.0.0", "npm"), "no candidates -> empty")
	// none above affected
	cands := []candidate{{version: "1.0.0", branch: "1", isExact: true}}
	assert.Equal(t, "", resolveCandidates(cands, "2.0.0", "npm"))
	// unknown ecosystem falls back to npm comparator and still resolves
	cands2 := []candidate{{version: "2.0.0", branch: "2", isExact: true}}
	assert.Equal(t, "2.0.0", resolveCandidates(cands2, "1.0.0", "docker-not-a-real-eco"))
}

func TestConfidenceFor(t *testing.T) {
	assert.Equal(t, model.ConfidenceHigh, confidenceFor(version.Fixed))
	assert.Equal(t, model.ConfidenceLower, confidenceFor(version.Affected))
	assert.Equal(t, model.ConfidenceLower, confidenceFor(version.Unknown))
}

func TestStripVCSHost(t *testing.T) {
	assert.Equal(t, "apple/swift-nio-http2", stripVCSHost("github.com/apple/swift-nio-http2"))
	assert.Equal(t, "g/p", stripVCSHost("gitlab.com/g/p"))
	assert.Equal(t, "o/r", stripVCSHost("bitbucket.org/o/r"))
	assert.Equal(t, "no/host", stripVCSHost("no/host"))
}

func TestMatchesIdentity(t *testing.T) {
	assert.True(t, matchesIdentity("golang.org/x/net", "pkg:golang/golang.org/x/net@v0.16.0", "golang.org/x/net"))
	assert.True(t, matchesIdentity("lodash", "", "lodash"), "name match when no PURL")
	assert.False(t, matchesIdentity("unrelated", "pkg:npm/lodash@1", "lodash"))
}

func TestDeriveFixVersion_UnparseableIsEmpty(t *testing.T) {
	occ := &model.Occurrence{DependencyName: "x", Ecosystem: "npm", AffectedVersion: "1.0.0"}
	assert.Equal(t, "", deriveFixVersion("", occ), "empty recommendation -> empty")
	assert.Equal(t, "", deriveFixVersion("no upgrade clause here", occ), "no clause -> empty")
}

func TestDeriveFixVersion_CompoundNoMatchingClause(t *testing.T) {
	// compound recommendation but neither clause names this occurrence
	occ := &model.Occurrence{DependencyName: "unrelated", Ecosystem: "npm", AffectedVersion: "1.0.0",
		PURL: "pkg:npm/unrelated@1.0.0"}
	rec := "Upgrade github.com/apple/swift-nio-http2 to version 1.28.0; Upgrade golang.org/x/net to version 0.17.0"
	assert.Equal(t, "", deriveFixVersion(rec, occ))
}

// TestDeriveFixVersion_CompoundNoSubstringConfusion: a compound recommendation
// must bind each occurrence to its exact package clause, never a substring.
// "foo" must not capture the "foobar" occurrence and hand it the wrong fix.
func TestDeriveFixVersion_CompoundNoSubstringConfusion(t *testing.T) {
	rec := "Upgrade foo to version 2.0.0; Upgrade foobar to version 5.0.0"

	foobar := &model.Occurrence{
		DependencyName: "foobar", Ecosystem: "npm", AffectedVersion: "1.0.0",
		PURL: "pkg:npm/foobar@1.0.0",
	}
	assert.Equal(t, "5.0.0", deriveFixVersion(rec, foobar),
		"foobar must bind to its own clause, not the foo substring")

	foo := &model.Occurrence{
		DependencyName: "foo", Ecosystem: "npm", AffectedVersion: "1.0.0",
		PURL: "pkg:npm/foo@1.0.0",
	}
	assert.Equal(t, "2.0.0", deriveFixVersion(rec, foo))
}

// TestIdentityMatch_MavenGroupIdGuard: a bare artifactId must not match a Maven
// occurrence in a different groupId. Maven identity comes from the groupId-aware
// PURL coordinate, never the bare-artifactId fallback.
func TestIdentityMatch_MavenGroupIdGuard(t *testing.T) {
	occ := model.Occurrence{
		DependencyName: "log4j-core", Ecosystem: "maven",
		PURL: "pkg:maven/com.evil/log4j-core@1.0.0",
	}
	// Bare artifactId, no groupId -> must NOT match a foreign group.
	assert.False(t, identityMatch(model.Change{DependencyName: "log4j-core"}, occ),
		"bare artifactId must not match across groupIds")
	// The occurrence's own group:artifact coordinate -> matches via the PURL.
	assert.True(t, identityMatch(model.Change{DependencyName: "com.evil:log4j-core"}, occ))
	// A different group's coordinate must not match.
	assert.False(t, identityMatch(model.Change{DependencyName: "org.apache.logging.log4j:log4j-core"}, occ))
}
