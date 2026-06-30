package main

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/verophi/verophi/internal/output"
	"github.com/verophi/verophi/pkg/model"
)

func TestCheckThresholds_NoLimit(t *testing.T) {
	result := &model.AnalysisResult{
		AdvisorySummary: model.AdvisorySummary{SeverityCounts: model.SeverityCounts{Critical: 5, High: 10}},
	}
	assert.NoError(t, checkThresholds(result, -1, -1))
}

func TestCheckThresholds_CriticalExceeded(t *testing.T) {
	result := &model.AnalysisResult{
		AdvisorySummary: model.AdvisorySummary{SeverityCounts: model.SeverityCounts{Critical: 5, High: 3}},
	}
	err := checkThresholds(result, 3, -1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "critical")
}

func TestCheckThresholds_HighExceeded(t *testing.T) {
	result := &model.AnalysisResult{
		AdvisorySummary: model.AdvisorySummary{SeverityCounts: model.SeverityCounts{Critical: 0, High: 10}},
	}
	err := checkThresholds(result, -1, 5)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "high")
}

func TestSelectMode(t *testing.T) {
	assert.Equal(t, output.ModeJSON, selectMode("json"))
	assert.Equal(t, output.ModeQuiet, selectMode("quiet"))
	assert.Equal(t, output.ModeCompact, selectMode("compact"))
	assert.Equal(t, output.ModeVerbose, selectMode("verbose"))
	assert.Equal(t, output.ModeDefault, selectMode("default"))
	assert.Equal(t, output.ModeDefault, selectMode("human"))
}

func TestEnvOrDefault(t *testing.T) {
	assert.Equal(t, "fallback", envOrDefault("NONEXISTENT_KEY_12345", "fallback"))
}

func TestEnvOrDefaultInt(t *testing.T) {
	assert.Equal(t, 42, envOrDefaultInt("NONEXISTENT_KEY_12345", 42))
}

func TestResolveFormat(t *testing.T) {
	assert.Equal(t, "verbose", resolveFormat("default", true, false))
	assert.Equal(t, "json", resolveFormat("json", true, true))
	assert.Equal(t, "compact", resolveFormat("compact", true, true))
	assert.Equal(t, "default", resolveFormat("default", false, false))
	assert.Equal(t, "json", resolveFormat("json", false, true))
}

func TestFormatFlagWiring(t *testing.T) {
	// --verbose selects verbose when --format is not explicitly set.
	cmd := newAnalyzeCmd()
	assert.NoError(t, cmd.Flags().Parse([]string{"--verbose"}))
	format, _ := cmd.Flags().GetString("format")
	verbose, _ := cmd.Flags().GetBool("verbose")
	mode := selectMode(resolveFormat(format, verbose, cmd.Flags().Changed("format")))
	assert.Equal(t, output.ModeVerbose, mode)

	// --verbose --format json stays json.
	cmd2 := newAnalyzeCmd()
	assert.NoError(t, cmd2.Flags().Parse([]string{"--verbose", "--format", "json"}))
	format2, _ := cmd2.Flags().GetString("format")
	verbose2, _ := cmd2.Flags().GetBool("verbose")
	mode2 := selectMode(resolveFormat(format2, verbose2, cmd2.Flags().Changed("format")))
	assert.Equal(t, output.ModeJSON, mode2)
}

// runAnalyze drives the analyze command with the given flags, capturing stdout,
// and returns the command error. It exercises the full RunE path (parse, build,
// analyze, render, thresholds) in the standalone (no-platform) flow.
func runAnalyze(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newAnalyzeCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs(args)

	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	runErr := cmd.Execute()
	_ = w.Close()
	os.Stdout = orig

	out, _ := io.ReadAll(r)
	return string(out), runErr
}

const sampleSBOM = "../../testdata/fixtures/sample-sbom.json"

func TestAnalyze_MissingSBOM(t *testing.T) {
	_, err := runAnalyze(t)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--sbom")
}

func TestAnalyze_BothPlatforms(t *testing.T) {
	_, err := runAnalyze(t, "--sbom", sampleSBOM, "--gitlab-project", "g/p", "--github-repo", "o/r")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot use both")
}

func TestAnalyze_InvalidSBOMPath(t *testing.T) {
	_, err := runAnalyze(t, "--sbom", "/nonexistent/sbom.json")
	require.Error(t, err)
	var te *thresholdExceededError
	assert.NotErrorAs(t, err, &te, "a parse error must not be a threshold error (exit 2, not 1)")
}

func TestAnalyze_StandaloneOK(t *testing.T) {
	out, err := runAnalyze(t, "--sbom", sampleSBOM, "--no-color")
	require.NoError(t, err)
	assert.Contains(t, out, "standalone (SBOM only)")
}

func TestAnalyze_GithubRepoInvalidFormat(t *testing.T) {
	_, err := runAnalyze(t, "--sbom", sampleSBOM, "--github-repo", "noslash")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "correlation failed")
	// The underlying cause is propagated (not a generic message), so the user
	// can see why correlation failed (auth, rate limit, bad repo, ...).
	assert.Contains(t, err.Error(), "owner/repo format")
}

func TestAnalyze_InvalidFormatRejected(t *testing.T) {
	_, err := runAnalyze(t, "--sbom", sampleSBOM, "--format", "jsonn")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --format")
	var te *thresholdExceededError
	assert.NotErrorAs(t, err, &te, "an invalid format must be an error (exit 2), not a threshold breach (exit 1)")
}

func TestAnalyze_MaxCriticalBreached(t *testing.T) {
	// sample SBOM has 2 critical
	_, err := runAnalyze(t, "--sbom", sampleSBOM, "--max-critical", "0", "--format", "quiet")
	require.Error(t, err)
	var te *thresholdExceededError
	assert.ErrorAs(t, err, &te, "threshold breach must be a thresholdExceededError (exit 1)")
	assert.Contains(t, err.Error(), "critical")
}

func TestAnalyze_MaxHighBreached(t *testing.T) {
	_, err := runAnalyze(t, "--sbom", sampleSBOM, "--max-high", "0", "--format", "quiet")
	require.Error(t, err)
	var te *thresholdExceededError
	assert.ErrorAs(t, err, &te)
	assert.Contains(t, err.Error(), "high")
}

func TestAnalyze_ThresholdsNotBreached(t *testing.T) {
	_, err := runAnalyze(t, "--sbom", sampleSBOM, "--max-critical", "5", "--max-high", "10", "--format", "quiet")
	require.NoError(t, err)
}

func TestAnalyze_QuietWritesNothing(t *testing.T) {
	out, err := runAnalyze(t, "--sbom", sampleSBOM, "--format", "quiet")
	require.NoError(t, err)
	assert.Empty(t, out)
}

// TestAnalyze_QuietBreachIsStdoutSilentButErrors locks the quiet contract: a
// threshold breach writes nothing to stdout but still returns the
// thresholdExceededError. main() routes that error to stderr and exits 1, so
// quiet silences normal output without hiding the failure reason (matching the
// common convention of grep -q / curl -s / git --quiet).
func TestAnalyze_QuietBreachIsStdoutSilentButErrors(t *testing.T) {
	out, err := runAnalyze(t, "--sbom", sampleSBOM, "--format", "quiet", "--max-critical", "0")
	assert.Empty(t, out, "quiet must not write to stdout even on a threshold breach")
	var te *thresholdExceededError
	require.ErrorAs(t, err, &te, "the breach must still surface as a thresholdExceededError (stderr + exit 1 in main)")
}

func TestAnalyze_JSONOutput(t *testing.T) {
	out, err := runAnalyze(t, "--sbom", sampleSBOM, "--format", "json")
	require.NoError(t, err)
	assert.Contains(t, out, `"schemaVersion": "1.0"`)
	assert.Contains(t, out, `"correlation"`)
}

func TestAnalyze_CycloneDX14(t *testing.T) {
	out, err := runAnalyze(t, "--sbom", "../../testdata/fixtures/sample-sbom-1.4.json", "--no-color")
	require.NoError(t, err)
	assert.Contains(t, out, "CVEs")
}

func TestVersionCmd(t *testing.T) {
	cmd := newVersionCmd()
	orig := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	cmd.Run(cmd, nil)
	_ = w.Close()
	os.Stdout = orig
	out, _ := io.ReadAll(r)
	assert.Contains(t, string(out), "verophi")
	assert.Contains(t, string(out), "commit:")
}

func TestSbomSourceFormat(t *testing.T) {
	assert.Equal(t, "", sbomSourceFormat(nil))
	assert.Equal(t, "", sbomSourceFormat(&model.SBOMResult{}))
	assert.Equal(t, "CycloneDX", sbomSourceFormat(&model.SBOMResult{Format: "CycloneDX"}))
	assert.Equal(t, "CycloneDX 1.7", sbomSourceFormat(&model.SBOMResult{Format: "CycloneDX", SpecVersion: "1.7"}))
}

func TestEnvOrDefault_Set(t *testing.T) {
	t.Setenv("VEROPHI_TEST_KEY", "value")
	assert.Equal(t, "value", envOrDefault("VEROPHI_TEST_KEY", "fallback"))
}

func TestEnvOrDefaultInt_Variants(t *testing.T) {
	t.Setenv("VEROPHI_TEST_INT", "42")
	assert.Equal(t, 42, envOrDefaultInt("VEROPHI_TEST_INT", 7))
	t.Setenv("VEROPHI_TEST_INT", "notanumber")
	assert.Equal(t, 7, envOrDefaultInt("VEROPHI_TEST_INT", 7))
}

func TestIsTTY_RegularAndClosed(t *testing.T) {
	// a pipe is not a character device
	_, w, _ := os.Pipe()
	assert.False(t, isTTY(w))
	// a closed file makes Stat fail -> false
	_ = w.Close()
	assert.False(t, isTTY(w))
}
