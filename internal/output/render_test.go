package output

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/verophi/verophi/pkg/model"
)

func TestRender_JSON(t *testing.T) {
	result := &model.AnalysisResult{
		SchemaVersion:          "1.0",
		Correlation:            model.Correlation{Status: model.CorrelationComplete},
		AdvisorySummary:        model.AdvisorySummary{Total: 1, Correlated: 1},
		TotalImpactScore:       8,
		ChangeRequests:         []model.ChangeRequest{},
		UncorrelatedAdvisories: []model.Advisory{},
	}
	var buf bytes.Buffer
	err := Render(result, Options{Mode: ModeJSON, Platform: ForPlatform("gitlab")}, &buf)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), `"schemaVersion": "1.0"`)
}

func TestRender_Quiet(t *testing.T) {
	result := &model.AnalysisResult{SchemaVersion: "1.0"}
	var buf bytes.Buffer
	err := Render(result, Options{Mode: ModeQuiet}, &buf)
	require.NoError(t, err)
	assert.Empty(t, buf.String())
}

func TestRender_Default_Standalone(t *testing.T) {
	result := &model.AnalysisResult{
		SchemaVersion:          "1.0",
		Correlation:            model.Correlation{Status: model.CorrelationNotRun},
		AdvisorySummary:        model.AdvisorySummary{Total: 5, SeverityCounts: model.SeverityCounts{Critical: 1, High: 2, Medium: 1, Low: 1}},
		TotalImpactScore:       19,
		ChangeRequests:         []model.ChangeRequest{},
		UncorrelatedAdvisories: []model.Advisory{},
	}
	var buf bytes.Buffer
	err := Render(result, Options{Mode: ModeDefault, Platform: ForPlatform("gitlab")}, &buf)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "standalone (SBOM only)")
	assert.Contains(t, buf.String(), "hint:")
}

func TestForPlatform(t *testing.T) {
	gl := ForPlatform("gitlab")
	assert.Equal(t, "merge request", gl.Noun())
	assert.Equal(t, "MR", gl.Abbrev())
	assert.Equal(t, "!42", gl.IDLabel(42))

	gh := ForPlatform("github")
	assert.Equal(t, "pull request", gh.Noun())
	assert.Equal(t, "PR", gh.Abbrev())
	assert.Equal(t, "#7", gh.IDLabel(7))
}

func makeCorrelatedResult() *model.AnalysisResult {
	me := 36.0
	red := 8.0
	return &model.AnalysisResult{
		SchemaVersion:        "1.0",
		Correlation:          model.Correlation{Status: model.CorrelationComplete, Platform: "gitlab", Repository: "g/p"},
		AdvisorySummary:      model.AdvisorySummary{Total: 3, Correlated: 1, Uncorrelated: 2, SeverityCounts: model.SeverityCounts{Critical: 1, High: 1, Low: 1}},
		TotalImpactScore:     13,
		ReducibleImpactScore: &red,
		ChangeRequests: []model.ChangeRequest{
			{
				Number: 5, URL: "https://gitlab.com/g/p/-/merge_requests/5", Title: "lodash",
				Platform: "gitlab", Status: model.StatusMatched, RiskTier: model.ChangePatch,
				ImpactScore: 8, MergeEfficiency: &me,
				Fixes: model.FixSummary{Total: 1, SeverityCounts: model.SeverityCounts{Critical: 1}},
				Assessments: []model.ChangeAssessment{
					{Change: model.Change{DependencyName: "lodash", CurrentVersion: "4.17.20", TargetVersion: "4.17.21", ChangeType: model.ChangePatch},
						AdvisoryMatches: []model.AdvisoryMatch{{Advisory: model.AdvisoryRef{ID: "CVE-1", Severity: model.SeverityCritical}}}},
				},
			},
			{
				Number: 60, URL: "https://gitlab.com/g/p/-/merge_requests/60", Title: "chalk",
				Platform: "gitlab", Status: model.StatusUnmatched, RiskTier: model.ChangeMajor,
				Assessments: []model.ChangeAssessment{
					{Change: model.Change{DependencyName: "chalk", CurrentVersion: "4.1.0", TargetVersion: "5.6.2", ChangeType: model.ChangeMajor}},
				},
			},
		},
		UncorrelatedAdvisories: []model.Advisory{
			{ID: "GHSA-353f-x4gh-cqq8", Severity: model.SeverityCritical,
				Occurrences: []model.Occurrence{{DependencyName: "nokogiri", AffectedVersion: "1.13.10"}}},
			{ID: "CVE-2023-1", Severity: model.SeverityHigh,
				Occurrences: []model.Occurrence{{DependencyName: "openssl", AffectedVersion: "1.1.1", FixVersion: "1.1.1n"}}},
		},
	}
}

// TestRender_GapHeadingsUseShortAbbrevUppercase guards the heading regression:
// headings must be fully uppercase and use the short MR/PR abbreviation, not the
// spelled-out mixed-case "Merge request".
func TestRender_GapHeadingsUseShortAbbrevUppercase(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Render(makeCorrelatedResult(), Options{Mode: ModeDefault, Platform: ForPlatform("gitlab")}, &buf))
	out := buf.String()
	assert.Contains(t, out, "CVEs WITHOUT A MATCHED MR")
	assert.Contains(t, out, "MRs WITHOUT A MATCHED CVE")
	assert.NotContains(t, out, "Merge request", "headings must use the MR abbreviation, not the spelled-out noun")
	// Per-entry fixes line (lodash: CR-VIS 8 critical -> fixes 1 CVE C:1).
	assert.Contains(t, out, "fixes 1 CVE  C:1 H:0 M:0 L:0")

	var buf2 bytes.Buffer
	require.NoError(t, Render(makeCorrelatedResult(), Options{Mode: ModeDefault, Platform: ForPlatform("github")}, &buf2))
	assert.Contains(t, buf2.String(), "CVEs WITHOUT A MATCHED PR")
	assert.Contains(t, buf2.String(), "PRs WITHOUT A MATCHED CVE")
	// summary count line must also use the platform abbreviation
	assert.Regexp(t, `PRs\s+\d+\s+matched: \d+`, buf2.String())
	assert.NotContains(t, buf2.String(), "MRs ", "github default must not show an MRs summary line")
}

// TestRender_LongGHSADoesNotOverflowDepColumn guards the column-width regression:
// the dependency must sit in a stable column even when a long GHSA id precedes it.
func TestRender_LongGHSADoesNotOverflowDepColumn(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Render(makeCorrelatedResult(), Options{Mode: ModeDefault, Platform: ForPlatform("gitlab")}, &buf))
	depCol := -1
	for _, line := range splitLines(buf.String()) {
		if idx := indexOfDep(line, "nokogiri@1.13.10"); idx >= 0 {
			depCol = idx
		}
		if idx := indexOfDep(line, "openssl@1.1.1"); idx >= 0 {
			if depCol >= 0 {
				assert.Equal(t, depCol, idx, "dep column must align regardless of id length (GHSA vs CVE)")
			}
		}
	}
	assert.GreaterOrEqual(t, depCol, 0, "expected a nokogiri gap line")
}

// TestRender_ContinuationIndentMatchesTitle guards the title/URL misalignment:
// the URL continuation line must start at the same column as the title.
func TestRender_ContinuationIndentMatchesTitle(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Render(makeCorrelatedResult(), Options{Mode: ModeDefault, Platform: ForPlatform("gitlab")}, &buf))
	lines := splitLines(buf.String())
	titleIdx := -1
	for i, line := range lines {
		if idx := indexOfDep(line, "lodash 4.17.20 -> 4.17.21"); idx >= 0 {
			titleIdx = idx
			// scan following continuation lines for the URL; it must align with the title
			for j := i + 1; j < len(lines); j++ {
				if u := indexOfDep(lines[j], "https://"); u >= 0 {
					assert.Equal(t, titleIdx, u, "URL continuation must align under the title column")
					break
				}
			}
		}
	}
	assert.GreaterOrEqual(t, titleIdx, 0, "expected the lodash ranked entry")
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	lines = append(lines, s[start:])
	return lines
}

func indexOfDep(line, sub string) int {
	for i := 0; i+len(sub) <= len(line); i++ {
		if line[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// TestRender_CompactPlatformAware guards that compact uses the platform
// abbreviation in the column header and summary tokens (PR/matched_prs on
// GitHub, MR/matched_mrs on GitLab), not a hardcoded MR.
func TestRender_CompactPlatformAware(t *testing.T) {
	var gh bytes.Buffer
	require.NoError(t, Render(makeCorrelatedResult(), Options{Mode: ModeCompact, Platform: ForPlatform("github")}, &gh))
	out := gh.String()
	assert.Contains(t, out, "matched_prs=")
	assert.NotContains(t, out, "matched_mrs=")
	// header id column is PR, not MR
	for _, line := range splitLines(out) {
		if indexOfDep(line, "RANK") >= 0 {
			assert.GreaterOrEqual(t, indexOfDep(line, "PR"), 0, "compact header must show PR on github")
			assert.Less(t, indexOfDep(line, " MR "), 0)
		}
	}

	var gl bytes.Buffer
	require.NoError(t, Render(makeCorrelatedResult(), Options{Mode: ModeCompact, Platform: ForPlatform("gitlab")}, &gl))
	assert.Contains(t, gl.String(), "matched_mrs=")
}

// TestRender_CompactHeaderRowAlignment guards that the column header and data
// rows share widths: the CVE-DEPS header label starts at the same column as the
// deps value in a row.
func TestRender_CompactHeaderRowAlignment(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Render(makeCorrelatedResult(), Options{Mode: ModeCompact, Platform: ForPlatform("gitlab")}, &buf))
	lines := splitLines(buf.String())
	var headerCol, rowCol int = -1, -1
	for _, line := range lines {
		if c := indexOfDep(line, "CVE-DEPS"); c >= 0 {
			headerCol = c
		}
		if indexOfDep(line, "lodash") >= 0 {
			if c := indexOfDep(line, "1/1"); c >= 0 {
				rowCol = c
			}
		}
	}
	assert.GreaterOrEqual(t, headerCol, 0, "expected CVE-DEPS header")
	assert.GreaterOrEqual(t, rowCol, 0, "expected a data row with 1/1")
	assert.Equal(t, headerCol, rowCol, "CVE-DEPS column header must align with the deps value")
}

// TestRender_CompactNoTrailingWhitespace guards that empty FLAGS leaves no
// trailing spaces on a row.
func TestRender_CompactNoTrailingWhitespace(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Render(makeCorrelatedResult(), Options{Mode: ModeCompact, Platform: ForPlatform("gitlab")}, &buf))
	for _, line := range splitLines(buf.String()) {
		if len(line) > 0 {
			assert.Equal(t, line, trimRightSpace(line), "compact line must not have trailing whitespace: %q", line)
		}
	}
}

func trimRightSpace(s string) string {
	for len(s) > 0 && s[len(s)-1] == ' ' {
		s = s[:len(s)-1]
	}
	return s
}

// TestRender_HeaderShowsSourceAndMatch guards the header carrying SBOM name,
// format, platform:repo, and the CVE match count.
func TestRender_HeaderShowsSourceAndMatch(t *testing.T) {
	var buf bytes.Buffer
	opts := Options{Mode: ModeDefault, Platform: ForPlatform("gitlab"), SBOMName: "sbom-frozen.json", SBOMFormat: "CycloneDX 1.7"}
	require.NoError(t, Render(makeCorrelatedResult(), opts, &buf))
	out := buf.String()
	assert.Contains(t, out, "sbom-frozen.json (CycloneDX 1.7)")
	assert.Contains(t, out, "gitlab:g/p")
	assert.Contains(t, out, "CVE match   1/3") // correlated 1, total 3
}

// TestRender_DefaultLimitsAllGapLists guards that every gap list, not only the
// CVE list, is capped at 5 in default mode with a "+N more" hint, and full in
// verbose.
func TestRender_DefaultLimitsAllGapLists(t *testing.T) {
	result := makeCorrelatedResult()
	// add 7 unmatched requests so the list exceeds the cap
	for i := 0; i < 7; i++ {
		result.ChangeRequests = append(result.ChangeRequests, model.ChangeRequest{
			Number: 100 + i, Platform: "gitlab", Status: model.StatusUnmatched, RiskTier: model.ChangeMinor,
			Assessments: []model.ChangeAssessment{{Change: model.Change{DependencyName: "x", CurrentVersion: "1", TargetVersion: "2"}}},
		})
	}
	var def bytes.Buffer
	require.NoError(t, Render(result, Options{Mode: ModeDefault, Platform: ForPlatform("gitlab")}, &def))
	assert.Contains(t, def.String(), "more (--verbose)", "default must cap the unmatched gap list")

	var vb bytes.Buffer
	require.NoError(t, Render(result, Options{Mode: ModeVerbose, Platform: ForPlatform("gitlab")}, &vb))
	// verbose shows all 8 unmatched (1 original chalk + 7 added); no truncation of that list
	assert.NotContains(t, vb.String(), "more (--verbose)")
}

// TestRender_VerboseDiagnosticBlock guards that verbose adds the per-request
// diagnostic block (status/age/risk/labels + per-child breakdown with Change-VIS,
// isolated efficiency, and full advisory ids) and known fix ranges for gaps,
// none of which the default view shows.
func TestRender_VerboseDiagnosticBlock(t *testing.T) {
	result := makeCorrelatedResult()
	// give the matched lodash CR an age and labels and a matched advisory id
	result.ChangeRequests[0].AgeDays = 9
	result.ChangeRequests[0].Labels = []string{"renovate"}

	var def bytes.Buffer
	require.NoError(t, Render(result, Options{Mode: ModeDefault, Platform: ForPlatform("gitlab")}, &def))
	assert.NotContains(t, def.String(), "status: matched", "default must not show the verbose detail block")
	assert.NotContains(t, def.String(), "KNOWN-FIX", "default gap table must not show the known-fix column")

	var vb bytes.Buffer
	require.NoError(t, Render(result, Options{Mode: ModeVerbose, Platform: ForPlatform("gitlab")}, &vb))
	out := vb.String()
	assert.Contains(t, out, "status: matched")
	assert.Contains(t, out, "age: 9d")
	assert.Contains(t, out, "risk: patch")
	assert.Contains(t, out, "labels: renovate")
	assert.Contains(t, out, "changes:")
	assert.Contains(t, out, "[CVE-1]", "per-child breakdown must list full advisory ids")

	// a stale request annotates its age with (stale)
	stale := makeCorrelatedResult()
	stale.ChangeRequests[0].AgeDays = 30
	stale.ChangeRequests[0].Stale = true
	var sb bytes.Buffer
	require.NoError(t, Render(stale, Options{Mode: ModeVerbose, Platform: ForPlatform("gitlab")}, &sb))
	assert.Contains(t, sb.String(), "age: 30d (stale)")
	// gap section shows the KNOWN-FIX column with the fix version under verbose
	// (openssl gap has FixVersion 1.1.1n set below)
	assert.Contains(t, out, "KNOWN-FIX")
	assert.Contains(t, out, "1.1.1n")
}

func makeStandaloneResult(n int) *model.AnalysisResult {
	advs := make([]model.Advisory, 0, n)
	for i := 0; i < n; i++ {
		advs = append(advs, model.Advisory{
			ID: fmt.Sprintf("CVE-2024-%04d", i), Severity: model.SeverityHigh,
			Occurrences: []model.Occurrence{{DependencyName: "pkg", AffectedVersion: "1.0.0", FixVersion: "1.2.0"}},
		})
	}
	return &model.AnalysisResult{
		SchemaVersion:          "1.0",
		Correlation:            model.Correlation{Status: model.CorrelationNotRun},
		AdvisorySummary:        model.AdvisorySummary{Total: n, Uncorrelated: n, SeverityCounts: model.SeverityCounts{High: n}},
		TotalImpactScore:       float64(4 * n),
		ChangeRequests:         []model.ChangeRequest{},
		UncorrelatedAdvisories: advs,
	}
}

// TestRender_StandaloneDefaultTableAndHint guards the SBOM-only default view:
// a SEV/ID/DEPENDENCY/KNOWN FIX table, capped at 20, with a platform-neutral hint.
func TestRender_StandaloneDefaultTable(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Render(makeStandaloneResult(25), Options{Mode: ModeDefault, Platform: ForPlatform("gitlab")}, &buf))
	out := buf.String()
	assert.Contains(t, out, "SEV")
	assert.Contains(t, out, "KNOWN FIX")
	assert.Contains(t, out, "+5 more (--verbose)", "default standalone caps at 20")
	assert.Contains(t, out, "to correlate change requests")
	assert.NotContains(t, out, "merge requests", "standalone hint must be platform-neutral")
}

// TestRender_StandaloneVerboseFull guards that verbose shows all CVEs.
func TestRender_StandaloneVerboseFull(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Render(makeStandaloneResult(25), Options{Mode: ModeVerbose, Platform: ForPlatform("gitlab")}, &buf))
	assert.NotContains(t, buf.String(), "more (--verbose)")
}

// TestRender_StandaloneCompactIsCVEList guards that standalone compact renders a
// CVE list, not the empty change-request table.
func TestRender_StandaloneCompactIsCVEList(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Render(makeStandaloneResult(3), Options{Mode: ModeCompact, Platform: ForPlatform("gitlab")}, &buf))
	out := buf.String()
	assert.Contains(t, out, "standalone")
	assert.Contains(t, out, "CVE-2024-0000")
	assert.NotContains(t, out, "RANK", "standalone compact must not show the MR table header")
	assert.NotContains(t, out, "matched_mrs", "standalone compact must not show the MR summary tokens")
}

// TestRender_ScoringNoteIsPlatformAware guards the clearer, platform-aware
// overlap note replacing the opaque "Row VIS values can overlap" line.
func TestRender_ScoringNoteIsPlatformAware(t *testing.T) {
	var gl bytes.Buffer
	require.NoError(t, Render(makeCorrelatedResult(), Options{Mode: ModeDefault, Platform: ForPlatform("gitlab")}, &gl))
	assert.Contains(t, gl.String(), "note: MR VIS can overlap; reducible VIS counts matched CVEs once.")
	assert.NotContains(t, gl.String(), "Row VIS values can overlap")

	var gh bytes.Buffer
	require.NoError(t, Render(makeCorrelatedResult(), Options{Mode: ModeDefault, Platform: ForPlatform("github")}, &gh))
	assert.Contains(t, gh.String(), "note: PR VIS can overlap")
}

// TestRender_ColorGatedOnTTY guards that severity color is emitted only when
// stdout is a TTY and color is not disabled, and never otherwise.
func TestRender_ColorGatedOnTTY(t *testing.T) {
	const esc = "\033["

	var on bytes.Buffer
	require.NoError(t, Render(makeCorrelatedResult(), Options{Mode: ModeDefault, Platform: ForPlatform("gitlab"), IsTTY: true}, &on))
	assert.Contains(t, on.String(), esc+"1;31m", "critical counts must be bold red on a TTY")

	var noColor bytes.Buffer
	require.NoError(t, Render(makeCorrelatedResult(), Options{Mode: ModeDefault, Platform: ForPlatform("gitlab"), IsTTY: true, NoColor: true}, &noColor))
	assert.NotContains(t, noColor.String(), esc, "no color when NoColor is set")

	var notTTY bytes.Buffer
	require.NoError(t, Render(makeCorrelatedResult(), Options{Mode: ModeDefault, Platform: ForPlatform("gitlab"), IsTTY: false}, &notTTY))
	assert.NotContains(t, notTTY.String(), esc, "no color when not a TTY")

	// Disabling color must be byte-identical to a non-TTY run (format unchanged).
	assert.Equal(t, notTTY.String(), noColor.String())
}

func TestSeverityChar(t *testing.T) {
	assert.Equal(t, "C", severityChar(model.SeverityCritical))
	assert.Equal(t, "H", severityChar(model.SeverityHigh))
	assert.Equal(t, "M", severityChar(model.SeverityMedium))
	assert.Equal(t, "L", severityChar(model.SeverityLow))
	assert.Equal(t, "?", severityChar(model.SeverityUnknown))
}

func TestSevAnsiAndWrap(t *testing.T) {
	assert.Equal(t, "1;31", sevAnsi("Critical"))
	assert.Equal(t, "", sevAnsi("Unknown"))
	on := colorizer{on: true}
	off := colorizer{on: false}
	assert.Equal(t, "x", off.wrap("Critical", "x"), "disabled colorizer is a no-op")
	assert.Equal(t, "x", on.wrap("Unknown", "x"), "no code for unknown severity")
	assert.Equal(t, "\033[1;31mx\033[0m", on.wrap("Critical", "x"))
}

func TestTruncate(t *testing.T) {
	assert.Equal(t, "short", truncate("short", 10))
	assert.Equal(t, "exactlyten", truncate("exactlyten", 10))
	assert.Equal(t, "verylo...", truncate("verylongstring", 9))
}

func TestBuildFlags(t *testing.T) {
	assert.Equal(t, "", buildFlags(model.ChangeRequest{
		Assessments: []model.ChangeAssessment{{}},
	}, gitlabPresenter{}, nil, nil))
	cr := model.ChangeRequest{
		Stale:          true,
		HasUnknownRisk: true,
		SplitCandidate: &model.SplitCandidate{DependencyName: "x"},
		Assessments:    []model.ChangeAssessment{{}, {}, {}},
	}
	assert.Equal(t, "stale,unknown,split,grouped:3", buildFlags(cr, gitlabPresenter{}, nil, nil))
	assert.Equal(t, "stale,unknown,split,grouped:3,needs:!84+!85",
		buildFlags(cr, gitlabPresenter{}, []int{84, 85}, nil))
	assert.Equal(t, "stale,unknown,split,grouped:3,partial:2",
		buildFlags(cr, gitlabPresenter{}, nil, []partialFix{{advisoryID: "A"}, {advisoryID: "B"}}))
}

func TestStandaloneDepAndFix_NoOccurrences(t *testing.T) {
	adv := model.Advisory{ID: "CVE-1"}
	assert.Equal(t, "", standaloneDep(adv))
	assert.Equal(t, "unknown", standaloneFix(adv))
}

func TestRender_UnparsedGapSection(t *testing.T) {
	result := makeCorrelatedResult()
	result.ChangeRequests = append(result.ChangeRequests, model.ChangeRequest{
		Number: 99, Platform: "gitlab", Status: model.StatusUnparsed, RiskTier: model.ChangeUnknown,
	})
	var buf bytes.Buffer
	require.NoError(t, Render(result, Options{Mode: ModeDefault, Platform: ForPlatform("gitlab")}, &buf))
	out := buf.String()
	assert.Contains(t, out, "MRs WITH NO CHANGES PARSED")
	assert.Contains(t, out, "!99")
}

// TestRender_GapTableFormatting guards the gap-section formatting contract:
// a column header on the CVE list and the MR list, the KNOWN-FIX column only in
// verbose, a NOTE column carrying the partially-addressed status, the request
// title on the no-changes-parsed list, and no "fixes 0" line for a VIS-0 request.
func TestRender_GapTableFormatting(t *testing.T) {
	result := makeCorrelatedResult()
	// partially addressed advisory: 2 occurrences, 1 addressed
	result.UncorrelatedAdvisories = append(result.UncorrelatedAdvisories, model.Advisory{
		ID: "CVE-2021-23337", Severity: model.SeverityHigh, AddressedOccurrences: 1,
		Occurrences: []model.Occurrence{
			{DependencyName: "lodash", AffectedVersion: "4.17.20", FixVersion: "4.17.21"},
			{DependencyName: "lodash-es", AffectedVersion: "4.17.20", FixVersion: "4.17.21"},
		},
	})
	// grouped VIS-0 request (one matched dep, no fully-addressed CVE) must not
	// emit a "fixes 0" line.
	result.ChangeRequests = append(result.ChangeRequests, model.ChangeRequest{
		Number: 70, URL: "u", Title: "split-candidate-group", Platform: "gitlab",
		Status: model.StatusMatched, RiskTier: model.ChangeMajor, ImpactScore: 0,
		Fixes: model.FixSummary{Total: 0},
		Assessments: []model.ChangeAssessment{
			{Change: model.Change{DependencyName: "minimist", ChangeType: model.ChangePatch}},
			{Change: model.Change{DependencyName: "ws", ChangeType: model.ChangeMajor}},
		},
	})
	// unparsed request carrying a title (R7: title shown on the parsed-gap list)
	result.ChangeRequests = append(result.ChangeRequests, model.ChangeRequest{
		Number: 99, Platform: "gitlab", Status: model.StatusUnparsed, RiskTier: model.ChangeUnknown,
		Title: "lock file maintenance",
	})

	var vb bytes.Buffer
	require.NoError(t, Render(result, Options{Mode: ModeVerbose, Platform: ForPlatform("gitlab")}, &vb))
	out := vb.String()

	// CVE-gap header columns
	assert.Regexp(t, `SEV\s+ID\s+DEPENDENCY\s+KNOWN-FIX\s+NOTE`, out)
	// NOTE column carries the partially-addressed status
	assert.Contains(t, out, "partially addressed (1/2 components)")
	// MR-gap header
	assert.Regexp(t, `MR\s+DESCRIPTION\s+RISK`, out)
	// no-changes-parsed shows the title
	assert.Contains(t, out, "lock file maintenance")
	// VIS-0 grouped request emits no "fixes 0" line
	assert.NotContains(t, out, "fixes 0")

	// default omits the KNOWN-FIX column
	var def bytes.Buffer
	require.NoError(t, Render(result, Options{Mode: ModeDefault, Platform: ForPlatform("gitlab")}, &def))
	assert.NotContains(t, def.String(), "KNOWN-FIX")
}

// TestRender_UnparsedDepsSurfaced guards R2: a matched request whose group had
// a dependency row that could not be parsed shows "(N unparsed)" on the deps
// line so the dropped dependency is not hidden.
func TestRender_UnparsedDepsSurfaced(t *testing.T) {
	result := makeCorrelatedResult()
	result.ChangeRequests[0].UnparsedDeps = 1 // matched lodash CR (1 matched dep)
	var buf bytes.Buffer
	require.NoError(t, Render(result, Options{Mode: ModeVerbose, Platform: ForPlatform("gitlab")}, &buf))
	assert.Contains(t, buf.String(), "deps: 1  with CVEs: 1  (1 unparsed)")
}
