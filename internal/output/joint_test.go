package output

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/verophi/verophi/pkg/model"
)

// jointResult builds a result where CVE-2023-44487 has two occurrences fixed by
// two different requests (!71 swift, !84 x/net). Neither fully addresses it
// alone, so both should get a "needs" line naming the other. !84 additionally
// fully fixes CVE-OWN on its own occurrence.
func jointResult() *model.AnalysisResult {
	swiftOcc := model.Occurrence{BOMRef: "swift", PURL: "pkg:swift/x@1", DependencyName: "swift-nio-http2"}
	netOcc := model.Occurrence{BOMRef: "net", PURL: "pkg:golang/x/net@1", DependencyName: "golang.org/x/net"}
	ownOcc := model.Occurrence{BOMRef: "own", PURL: "pkg:golang/x/net@1", DependencyName: "golang.org/x/net"}

	red := 4.0
	me0 := 0.0
	me8 := 8.0
	return &model.AnalysisResult{
		SchemaVersion:        "1.0",
		Correlation:          model.Correlation{Status: model.CorrelationComplete, Platform: "gitlab", Repository: "g/p"},
		AdvisorySummary:      model.AdvisorySummary{Total: 2, Correlated: 2},
		TotalImpactScore:     8,
		ReducibleImpactScore: &red,
		ChangeRequests: []model.ChangeRequest{
			{
				Number: 84, Platform: "gitlab", Title: "x/net", Status: model.StatusMatched,
				RiskTier: model.ChangeMinor, ImpactScore: 8, MergeEfficiency: &me8,
				Fixes: model.FixSummary{Total: 1, SeverityCounts: model.SeverityCounts{High: 1}},
				Assessments: []model.ChangeAssessment{{
					Change: model.Change{DependencyName: "golang.org/x/net", CurrentVersion: "1", TargetVersion: "2"},
					AdvisoryMatches: []model.AdvisoryMatch{
						{Advisory: model.AdvisoryRef{ID: "CVE-OWN", Severity: model.SeverityHigh}, Occurrence: ownOcc},
						{Advisory: model.AdvisoryRef{ID: "CVE-2023-44487", Severity: model.SeverityHigh}, Occurrence: netOcc},
					},
				}},
			},
			{
				Number: 71, Platform: "gitlab", Title: "swift-nio-http2", Status: model.StatusMatched,
				RiskTier: model.ChangeMinor, ImpactScore: 0, MergeEfficiency: &me0,
				Fixes: model.FixSummary{},
				Assessments: []model.ChangeAssessment{{
					Change: model.Change{DependencyName: "swift-nio-http2", CurrentVersion: "1", TargetVersion: "2"},
					AdvisoryMatches: []model.AdvisoryMatch{
						{Advisory: model.AdvisoryRef{ID: "CVE-2023-44487", Severity: model.SeverityHigh}, Occurrence: swiftOcc},
					},
				}},
			},
		},
		UncorrelatedAdvisories: []model.Advisory{},
	}
}

func TestComputeJointFixes(t *testing.T) {
	jm := computeJointFixes(jointResult())

	// !71 only covers the swift occurrence -> needs !84.
	require.Len(t, jm[71], 1)
	assert.Equal(t, "CVE-2023-44487", jm[71][0].advisoryID)
	assert.Equal(t, []int{84}, jm[71][0].partners)

	// !84 covers the net occurrence of CVE-2023-44487 (partial) -> needs !71.
	// It fully fixes CVE-OWN alone, so that one is NOT a joint fix.
	require.Len(t, jm[84], 1)
	assert.Equal(t, "CVE-2023-44487", jm[84][0].advisoryID)
	assert.Equal(t, []int{71}, jm[84][0].partners)
}

// TestRender_JointFixLine guards the "needs" line in default mode and that the
// "fixes 0 CVEs" line is dropped when the only contribution is a joint fix.
func TestRender_JointFixLine(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Render(jointResult(), Options{Mode: ModeDefault, Platform: ForPlatform("gitlab")}, &buf))
	out := buf.String()

	assert.Contains(t, out, "needs !84 to fully fix CVE-2023-44487")
	assert.Contains(t, out, "needs !71 to fully fix CVE-2023-44487")
	// !71 contributes only the joint fix -> no "fixes 0 CVEs" line for it.
	for _, line := range splitLines(out) {
		if indexOfDep(line, "swift-nio-http2 1 -> 2") >= 0 {
			// the entry header line; the following lines must not contain "fixes 0 CVEs"
		}
	}
	assert.NotContains(t, out, "fixes 0 CVEs")
	// !84 fully fixes CVE-OWN -> keeps its fixes line (singular for 1).
	assert.Contains(t, out, "fixes 1 CVE")
}

// TestRender_JointFixGitHubNouns guards platform-aware ids in the needs line.
func TestRender_JointFixGitHubNouns(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Render(jointResult(), Options{Mode: ModeDefault, Platform: ForPlatform("github")}, &buf))
	out := buf.String()
	assert.Contains(t, out, "needs #84 to fully fix CVE-2023-44487")
	assert.Contains(t, out, "needs #71 to fully fix CVE-2023-44487")
}

// TestRender_JointFixCompactFlag guards the needs flag in compact mode.
func TestRender_JointFixCompactFlag(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Render(jointResult(), Options{Mode: ModeCompact, Platform: ForPlatform("gitlab")}, &buf))
	out := buf.String()
	assert.Contains(t, out, "needs:!84")
	assert.Contains(t, out, "needs:!71")
}

// TestComputeJointFixes_FullyAddressedAloneNoNote guards that a request fully
// addressing a single-occurrence advisory gets no joint note.
func TestComputeJointFixes_FullyAddressedAloneNoNote(t *testing.T) {
	occ := model.Occurrence{BOMRef: "a", PURL: "pkg:npm/lodash@1"}
	jm := computeJointFixes(&model.AnalysisResult{
		ChangeRequests: []model.ChangeRequest{{
			Number: 5, Status: model.StatusMatched,
			Assessments: []model.ChangeAssessment{{
				AdvisoryMatches: []model.AdvisoryMatch{
					{Advisory: model.AdvisoryRef{ID: "CVE-1", Severity: model.SeverityHigh}, Occurrence: occ},
				},
			}},
		}},
		UncorrelatedAdvisories: []model.Advisory{},
	})
	assert.Empty(t, jm[5])
}

// TestComputeJointFixes_PartialNotCollectivelyFixable guards Fall 2: an advisory
// in UncorrelatedAdvisories (a component has no fix) yields no joint note.
func TestComputeJointFixes_PartialNotCollectivelyFixable(t *testing.T) {
	occ := model.Occurrence{BOMRef: "a", PURL: "pkg:npm/x@1"}
	jm := computeJointFixes(&model.AnalysisResult{
		ChangeRequests: []model.ChangeRequest{{
			Number: 5, Status: model.StatusMatched,
			Assessments: []model.ChangeAssessment{{
				AdvisoryMatches: []model.AdvisoryMatch{
					{Advisory: model.AdvisoryRef{ID: "CVE-PARTIAL", Severity: model.SeverityHigh}, Occurrence: occ},
				},
			}},
		}},
		UncorrelatedAdvisories: []model.Advisory{
			{ID: "CVE-PARTIAL", Severity: model.SeverityHigh, AddressedOccurrences: 1,
				Occurrences: []model.Occurrence{occ, {BOMRef: "b", PURL: "pkg:npm/y@1"}}},
		},
	})
	assert.Empty(t, jm[5])
}
