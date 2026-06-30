package output

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/verophi/verophi/pkg/model"
)

// TestRender_StandaloneFailedMode covers the failed-correlation header variant:
// when the platform query failed (not merely absent), the standalone view labels
// itself "platform query failed".
func TestRender_StandaloneFailedMode(t *testing.T) {
	result := makeCorrelatedResult()
	result.Correlation.Status = model.CorrelationFailed
	var buf bytes.Buffer
	require.NoError(t, Render(result, Options{Mode: ModeDefault, Platform: ForPlatform("gitlab")}, &buf))
	require.Contains(t, buf.String(), "standalone (platform query failed)")
}

// TestRender_StandaloneCapsLongDependency covers the dependency-column cap in the
// standalone width sizing: a dependency string longer than the cap must not blow
// the column width past it.
func TestRender_StandaloneCapsLongDependency(t *testing.T) {
	longName := strings.Repeat("verylongdependencyname", 3) // > 40 chars
	result := &model.AnalysisResult{
		SchemaVersion:   "1.0",
		Correlation:     model.Correlation{Status: model.CorrelationNotRun},
		AdvisorySummary: model.AdvisorySummary{Total: 1, Uncorrelated: 1, SeverityCounts: model.SeverityCounts{High: 1}},
		ChangeRequests:  []model.ChangeRequest{},
		UncorrelatedAdvisories: []model.Advisory{
			{ID: "CVE-1", Severity: model.SeverityHigh,
				Occurrences: []model.Occurrence{{DependencyName: longName, AffectedVersion: "1.0.0"}}},
		},
	}
	idW, depW := standaloneColWidths(result.UncorrelatedAdvisories)
	require.Equal(t, 40, depW, "dependency column is capped at 40")
	require.GreaterOrEqual(t, idW, len("ID"))
}

func makeGroupedMatchedResult() *model.AnalysisResult {
	me := 8.0
	red := 8.0
	return &model.AnalysisResult{
		SchemaVersion:        "1.0",
		Correlation:          model.Correlation{Status: model.CorrelationComplete, Platform: "gitlab", Repository: "g/p"},
		AdvisorySummary:      model.AdvisorySummary{Total: 1, Correlated: 1, SeverityCounts: model.SeverityCounts{Critical: 1}},
		TotalImpactScore:     8,
		ReducibleImpactScore: &red,
		ChangeRequests: []model.ChangeRequest{
			{
				Number: 70, URL: "https://gitlab.com/g/p/-/merge_requests/70", Title: "http-client group",
				Platform: "gitlab", Status: model.StatusMatched, RiskTier: model.ChangeMajor,
				ImpactScore: 8, MergeEfficiency: &me,
				Fixes: model.FixSummary{Total: 1, SeverityCounts: model.SeverityCounts{Critical: 1}},
				SplitCandidate: &model.SplitCandidate{
					DependencyName: "axios", ImpactScore: 8, ShareOfRequest: 1.0,
					RiskTier: model.ChangePatch, MergeEfficiency: 8.0,
				},
				Assessments: []model.ChangeAssessment{
					{Change: model.Change{DependencyName: "axios", CurrentVersion: "0.21.1", TargetVersion: "1.6.0", ChangeType: model.ChangePatch},
						ImpactScore:     8,
						AdvisoryMatches: []model.AdvisoryMatch{{Advisory: model.AdvisoryRef{ID: "CVE-1", Severity: model.SeverityCritical}}}},
					{Change: model.Change{DependencyName: "got", CurrentVersion: "11.0.0", TargetVersion: "12.0.0", ChangeType: model.ChangeMajor}},
				},
			},
		},
		UncorrelatedAdvisories: []model.Advisory{},
	}
}

// TestRender_GroupedSplitAndMatchedDeps covers the grouped ranked entry: the
// "deps: N  with CVEs: M" line (more than one assessment) and the "split:" line
// (SplitCandidate present).
func TestRender_GroupedSplitAndMatchedDeps(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Render(makeGroupedMatchedResult(), Options{Mode: ModeDefault, Platform: ForPlatform("gitlab")}, &buf))
	out := buf.String()
	require.Contains(t, out, "deps: 2  with CVEs: 1")
	require.Contains(t, out, "split: axios")
}

// TestRender_VerboseEmptyAdvisoryIDs covers advisoryIDs returning empty for a
// child with no matches: the unmatched "got" child must render no id bracket
// while the matched "axios" child shows [CVE-1].
func TestRender_VerboseEmptyAdvisoryIDs(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Render(makeGroupedMatchedResult(), Options{Mode: ModeVerbose, Platform: ForPlatform("gitlab")}, &buf))
	out := buf.String()
	require.Contains(t, out, "[CVE-1]")
	for _, line := range splitLines(out) {
		if strings.Contains(line, "got 11.0.0 -> 12.0.0") {
			require.NotContains(t, line, "[", "unmatched child must render no advisory id bracket")
		}
	}
}

// TestRender_CVEGapListCapped covers the "+N more" truncation of the CVE gap
// list in default mode when there are more than five uncorrelated advisories.
func TestRender_CVEGapListCapped(t *testing.T) {
	result := makeCorrelatedResult()
	result.UncorrelatedAdvisories = nil
	for i := 0; i < 8; i++ {
		result.UncorrelatedAdvisories = append(result.UncorrelatedAdvisories, model.Advisory{
			ID: fmt.Sprintf("CVE-2024-%04d", i), Severity: model.SeverityHigh,
			Occurrences: []model.Occurrence{{DependencyName: "pkg", AffectedVersion: "1.0.0"}},
		})
	}
	var buf bytes.Buffer
	require.NoError(t, Render(result, Options{Mode: ModeDefault, Platform: ForPlatform("gitlab")}, &buf))
	require.Contains(t, buf.String(), "+3 more (--verbose)", "8 uncorrelated CVEs, cap 5 -> +3 more")
}

// TestRender_PartiallyAddressedGapLine covers the gap annotation for an advisory
// that is only partially addressed: it stays uncorrelated but shows how many of
// its components are covered.
func TestRender_PartiallyAddressedGapLine(t *testing.T) {
	result := makeCorrelatedResult()
	result.UncorrelatedAdvisories = []model.Advisory{
		{ID: "CVE-PARTIAL", Severity: model.SeverityHigh, AddressedOccurrences: 1,
			Occurrences: []model.Occurrence{
				{DependencyName: "lib", AffectedVersion: "1.0.0"},
				{DependencyName: "lib", AffectedVersion: "1.0.0"},
			}},
	}
	var buf bytes.Buffer
	require.NoError(t, Render(result, Options{Mode: ModeDefault, Platform: ForPlatform("gitlab")}, &buf))
	require.Contains(t, buf.String(), "partially addressed (1/2 components)")
}

// TestRender_HeaderNameWithoutFormat covers the header branch where an SBOM name
// is supplied without a format string.
func TestRender_HeaderNameWithoutFormat(t *testing.T) {
	var buf bytes.Buffer
	opts := Options{Mode: ModeDefault, Platform: ForPlatform("gitlab"), SBOMName: "sbom.json"}
	require.NoError(t, Render(makeCorrelatedResult(), opts, &buf))
	out := buf.String()
	require.Contains(t, out, "  sbom.json")
	require.NotContains(t, out, "sbom.json (")
}
