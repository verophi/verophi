package analysis

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/verophi/verophi/pkg/model"
)

// TestComputeSplitCandidate_Qualifies covers the split-hint selection: a
// lower-risk child (patch, risk 1) inside a major request (risk 3) that carries
// a dominant share of the request VIS is surfaced as the split candidate, with
// its isolated efficiency (Change-VIS / child risk).
func TestComputeSplitCandidate_Qualifies(t *testing.T) {
	eff := 4.0
	cr := &model.ChangeRequest{
		RiskTier:        model.ChangeMajor, // risk 3
		ImpactScore:     10,
		MergeEfficiency: &eff,
		Assessments: []model.ChangeAssessment{
			{Change: model.Change{DependencyName: "lowrisk", ChangeType: model.ChangePatch}, ImpactScore: 8},
			{Change: model.Change{DependencyName: "highrisk", ChangeType: model.ChangeMajor}, ImpactScore: 2},
		},
	}
	sc := computeSplitCandidate(cr)
	require.NotNil(t, sc)
	assert.Equal(t, "lowrisk", sc.DependencyName)
	assert.Equal(t, 8.0, sc.ImpactScore)
	assert.InDelta(t, 0.8, sc.ShareOfRequest, 0.001)
	assert.Equal(t, model.ChangePatch, sc.RiskTier)
	assert.Equal(t, 8.0, sc.MergeEfficiency) // 8 / risk 1
}

// TestComputeSplitCandidate_TieBreakByName covers the efficiency-based qualifier
// (childVME >= 1.5 * CR-VME) and the deterministic tie-break: equal share
// resolves to the lexicographically smaller dependency name.
func TestComputeSplitCandidate_TieBreakByName(t *testing.T) {
	eff := 4.0
	cr := &model.ChangeRequest{
		RiskTier:        model.ChangeMajor,
		ImpactScore:     16,
		MergeEfficiency: &eff,
		Assessments: []model.ChangeAssessment{
			{Change: model.Change{DependencyName: "zebra", ChangeType: model.ChangePatch}, ImpactScore: 8},
			{Change: model.Change{DependencyName: "alpha", ChangeType: model.ChangePatch}, ImpactScore: 8},
		},
	}
	sc := computeSplitCandidate(cr)
	require.NotNil(t, sc)
	assert.Equal(t, "alpha", sc.DependencyName, "equal share -> lexicographically smaller name wins")
}

// TestComputeSplitCandidate_None covers the guards and the no-qualifying-child
// path: unknown risk, nil VME, and a request whose children are all either at or
// above the risk tier or below the VIS floor.
func TestComputeSplitCandidate_None(t *testing.T) {
	assert.Nil(t, computeSplitCandidate(&model.ChangeRequest{HasUnknownRisk: true}), "unknown risk -> nil")
	assert.Nil(t, computeSplitCandidate(&model.ChangeRequest{}), "nil VME -> nil")

	eff := 4.0
	cr := &model.ChangeRequest{
		RiskTier:        model.ChangeMajor,
		ImpactScore:     10,
		MergeEfficiency: &eff,
		Assessments: []model.ChangeAssessment{
			{Change: model.Change{ChangeType: model.ChangeMajor}, ImpactScore: 8}, // risk >= tier
			{Change: model.Change{ChangeType: model.ChangePatch}, ImpactScore: 2}, // VIS < 4
		},
	}
	assert.Nil(t, computeSplitCandidate(cr), "no child qualifies")
}

// TestComputeFlags_Branches covers the per-request flag computation: unparsed
// requests are skipped entirely; a request with a risk-0 child is infectiously
// unknown (nil VME); and age over 14 days flags stale.
func TestComputeFlags_Branches(t *testing.T) {
	reqs := []model.ChangeRequest{
		{Status: model.StatusUnparsed},
		{
			Status: model.StatusMatched, AgeDays: 20, ImpactScore: 8,
			Assessments: []model.ChangeAssessment{
				{Change: model.Change{ChangeType: model.ChangeDigest}}, // risk 0
				{Change: model.Change{ChangeType: model.ChangePatch}, ImpactScore: 8},
			},
		},
	}
	computeFlags(reqs, 14)

	assert.Equal(t, model.ChangeType{}, reqs[0].RiskTier, "unparsed request left untouched")
	assert.True(t, reqs[1].HasUnknownRisk)
	assert.Nil(t, reqs[1].MergeEfficiency, "any risk-0 child -> no CR-VME")
	assert.True(t, reqs[1].Stale, "age 20 > 14 -> stale")
}

// TestComputeFlags_StaleThresholdConfigurable covers the configurable stale-days
// threshold: a custom threshold shifts the cutoff, and 0 disables the mark.
func TestComputeFlags_StaleThresholdConfigurable(t *testing.T) {
	mk := func() []model.ChangeRequest {
		return []model.ChangeRequest{{
			Status: model.StatusMatched, AgeDays: 20, ImpactScore: 8,
			Assessments: []model.ChangeAssessment{
				{Change: model.Change{ChangeType: model.ChangePatch}, ImpactScore: 8},
			},
		}}
	}

	custom := mk()
	computeFlags(custom, 30)
	assert.False(t, custom[0].Stale, "age 20 <= 30 -> not stale")

	disabled := mk()
	computeFlags(disabled, 0)
	assert.False(t, disabled[0].Stale, "stale-days 0 disables the mark")

	tight := mk()
	computeFlags(tight, 7)
	assert.True(t, tight[0].Stale, "age 20 > 7 -> stale")
}

// TestScoreCRVIS_SkipsNonMatched covers the guard that only matched requests get
// a CR-VIS; an unmatched request keeps a zero score.
func TestScoreCRVIS_SkipsNonMatched(t *testing.T) {
	reqs := []model.ChangeRequest{{
		Status: model.StatusUnmatched,
		Assessments: []model.ChangeAssessment{
			{Change: model.Change{DependencyName: "x"}, ImpactScore: 8},
		},
	}}
	scoreCRVIS(nil, reqs)
	assert.Equal(t, 0.0, reqs[0].ImpactScore)
}

// TestRequestFullyAddresses_Edges covers the no-occurrence advisory (cannot be
// fully addressed) and the partial case (one of two occurrences matched).
func TestRequestFullyAddresses_Edges(t *testing.T) {
	assert.False(t, requestFullyAddresses(&model.ChangeRequest{}, &model.Advisory{ID: "CVE-X"}),
		"advisory with no occurrences is not fully addressed")

	occ1 := model.Occurrence{BOMRef: "a", PURL: "a"}
	occ2 := model.Occurrence{BOMRef: "b", PURL: "b"}
	adv := &model.Advisory{ID: "CVE-X", Occurrences: []model.Occurrence{occ1, occ2}}
	cr := &model.ChangeRequest{Assessments: []model.ChangeAssessment{
		{AdvisoryMatches: []model.AdvisoryMatch{
			{Advisory: model.AdvisoryRef{ID: "CVE-X"}, Occurrence: occ1},
		}},
	}}
	assert.False(t, requestFullyAddresses(cr, adv), "only one of two occurrences matched")
}

// TestCollectivelyAddressed_NoOccurrence covers the no-occurrence guard.
func TestCollectivelyAddressed_NoOccurrence(t *testing.T) {
	assert.False(t, collectivelyAddressed(&model.Advisory{ID: "CVE-X"}, nil))
}

// TestCorrelate_NoFixVersionSkipped covers the occurrence skip when the advisory
// carries no parseable recommendation: no fix version, no match, and a parsed
// request with no matches becomes unmatched.
func TestCorrelate_NoFixVersionSkipped(t *testing.T) {
	advisories := []model.Advisory{{
		ID: "CVE-X", Severity: model.SeverityHigh, Recommendation: "",
		Occurrences: []model.Occurrence{
			{PURL: "pkg:npm/x@1.0.0", DependencyName: "x", Ecosystem: "npm", AffectedVersion: "1.0.0"},
		},
	}}
	requests := []model.ChangeRequest{{
		Number: 1, Status: model.StatusParsed,
		Assessments: []model.ChangeAssessment{
			{Change: model.Change{DependencyName: "x", TargetVersion: "2.0.0"}},
		},
	}}

	correlate(advisories, requests)

	assert.Equal(t, model.StatusUnmatched, requests[0].Status)
	assert.Empty(t, requests[0].Assessments[0].AdvisoryMatches)
}

// TestExtractPURLName_StripsQualifier covers the query-qualifier strip in a PURL
// that has no version segment (e.g. a Maven coordinate with ?type=jar).
func TestExtractPURLName_StripsQualifier(t *testing.T) {
	assert.Equal(t, "maven/org.apache/log4j-core",
		extractPURLName("pkg:maven/org.apache/log4j-core?type=jar"))
}

// TestIdentityMatch_MalformedPURLCoordinate covers the guard for a PURL whose
// coordinate has no namespace separator: the coordinate match bails and the
// ecosystem-aware name fallback decides.
func TestIdentityMatch_MalformedPURLCoordinate(t *testing.T) {
	occ := model.Occurrence{PURL: "pkg:npm", DependencyName: "lodash", Ecosystem: "npm"}
	change := model.Change{DependencyName: "lodash"}
	assert.True(t, identityMatch(change, occ), "falls through to name normalization when PURL coordinate is malformed")
}

// TestOrderResult_RemainingTieBreaks covers the deepest deterministic tie-break
// keys (R11) the primary ordering test does not reach: change requests by number
// when VIS and VME are equal; advisory matches by id then occurrence PURL when
// weights are equal.
func TestOrderResult_RemainingTieBreaks(t *testing.T) {
	eff := 5.0
	result := &model.AnalysisResult{
		ChangeRequests: []model.ChangeRequest{
			{Number: 5, ImpactScore: 10, MergeEfficiency: &eff},
			{Number: 2, ImpactScore: 10, MergeEfficiency: &eff,
				Assessments: []model.ChangeAssessment{
					{Change: model.Change{DependencyName: "dup"}, ImpactScore: 4,
						AdvisoryMatches: []model.AdvisoryMatch{
							{Advisory: model.AdvisoryRef{ID: "CVE-2", Severity: model.SeverityHigh}, Occurrence: model.Occurrence{PURL: "x", BOMRef: "b"}},
							{Advisory: model.AdvisoryRef{ID: "CVE-1", Severity: model.SeverityHigh}, Occurrence: model.Occurrence{PURL: "y", BOMRef: "b"}},
							{Advisory: model.AdvisoryRef{ID: "CVE-1", Severity: model.SeverityHigh}, Occurrence: model.Occurrence{PURL: "x", BOMRef: "b"}},
						}},
				}},
		},
	}

	orderResult(result)

	// Equal VIS and VME -> number ascending.
	assert.Equal(t, 2, result.ChangeRequests[0].Number)
	assert.Equal(t, 5, result.ChangeRequests[1].Number)

	// Equal weight -> id ascending, then occurrence PURL ascending.
	m := result.ChangeRequests[0].Assessments[0].AdvisoryMatches
	assert.Equal(t, "CVE-1", m[0].Advisory.ID)
	assert.Equal(t, "x", m[0].Occurrence.PURL)
	assert.Equal(t, "CVE-1", m[1].Advisory.ID)
	assert.Equal(t, "y", m[1].Occurrence.PURL)
	assert.Equal(t, "CVE-2", m[2].Advisory.ID)
}

// TestParseTokens_SkipsEmptyTokens covers the empty-token skip from a trailing or
// doubled comma in a bare version list.
func TestParseTokens_SkipsEmptyTokens(t *testing.T) {
	cands := parseTokens("1.0.0, , 2.0.0,")
	var got []string
	for _, c := range cands {
		got = append(got, c.version)
	}
	assert.Equal(t, []string{"1.0.0", "2.0.0"}, got)
}
