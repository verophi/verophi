package sbom

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCycloneDX_FrozenFixture(t *testing.T) {
	path := "../../../verophi-inttest/out/sboms/sbom-frozen.json"
	// Skip if fixture not available (CI or different checkout)
	result, err := ParseCycloneDX(path, 0)
	if err != nil {
		t.Skipf("fixture not available: %v", err)
	}

	require.NotNil(t, result)
	assert.Equal(t, "CycloneDX", result.Format)
	assert.Equal(t, "1.7", result.SpecVersion)

	// Known counts from the fixture
	assert.Equal(t, 136, len(result.Advisories), "expected 136 advisories")

	// Check that every advisory has at least one occurrence
	for _, adv := range result.Advisories {
		assert.NotEmpty(t, adv.ID)
		assert.NotEmpty(t, adv.Occurrences, "advisory %s should have occurrences", adv.ID)

		for _, occ := range adv.Occurrences {
			assert.NotEmpty(t, occ.BOMRef, "occurrence in %s missing BOMRef", adv.ID)
			assert.NotEmpty(t, occ.PURL, "occurrence in %s missing PURL", adv.ID)
			assert.NotEmpty(t, occ.AffectedVersion, "occurrence in %s missing AffectedVersion", adv.ID)
			assert.NotEmpty(t, occ.Ecosystem, "occurrence in %s missing Ecosystem", adv.ID)
		}
	}

	// Verify recommendation is preserved
	var foundAxios bool
	for _, adv := range result.Advisories {
		if adv.ID == "CVE-2026-42033" {
			foundAxios = true
			assert.Contains(t, adv.Recommendation, "1.15.1, 0.31.1")
			assert.Equal(t, 1, len(adv.Occurrences))
			assert.Equal(t, "0.21.1", adv.Occurrences[0].AffectedVersion)
			assert.Equal(t, "npm", adv.Occurrences[0].Ecosystem)
		}
	}
	assert.True(t, foundAxios, "CVE-2026-42033 (axios) not found")

	// Verify compound recommendation (CVE-2023-44487 with 2 occurrences)
	var found44487 bool
	for _, adv := range result.Advisories {
		if adv.ID == "CVE-2023-44487" {
			found44487 = true
			assert.Contains(t, adv.Recommendation, "swift-nio-http2")
			assert.Contains(t, adv.Recommendation, "golang.org/x/net")
			assert.GreaterOrEqual(t, len(adv.Occurrences), 2)
		}
	}
	assert.True(t, found44487, "CVE-2023-44487 not found")
}

func TestParseCycloneDX_FileNotFound(t *testing.T) {
	_, err := ParseCycloneDX("/nonexistent/path.json", 0)
	assert.Error(t, err)
}

func TestEcosystemFromPURL(t *testing.T) {
	tests := []struct {
		purl     string
		expected string
	}{
		{"pkg:npm/axios@1.6.0", "npm"},
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "maven"},
		{"pkg:golang/github.com/gin-gonic/gin@v1.7.0", "go"},
		{"pkg:gem/actionpack@6.1.4", "gem"},
		{"pkg:cargo/tokio@1.17.0", "cargo"},
		{"pkg:nuget/Newtonsoft.Json@12.0.0", "nuget"},
		{"pkg:swift/github.com/apple/swift-nio-http2@1.25.0", "swift"},
		{"pkg:hex/phoenix@1.0.0", "hex"},
		{"pkg:pub/flutter@3.0.0", "pub"},
		{"pkg:composer/laravel/framework@9.0.0", "composer"},
		{"", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.purl, func(t *testing.T) {
			got := ecosystemFromPURL(tt.purl)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestParseCycloneDX_ErrorPaths(t *testing.T) {
	dir := t.TempDir()

	// not a regular file (a directory)
	_, err := ParseCycloneDX(dir, 0)
	assert.Error(t, err)

	// size limit exceeded
	big := dir + "/big.json"
	require.NoError(t, os.WriteFile(big, []byte(`{"bomFormat":"CycloneDX"}`), 0o600))
	_, err = ParseCycloneDX(big, 1) // 1 byte limit
	assert.ErrorContains(t, err, "exceeds size limit")

	// invalid JSON
	bad := dir + "/bad.json"
	require.NoError(t, os.WriteFile(bad, []byte(`not json`), 0o600))
	_, err = ParseCycloneDX(bad, 0)
	assert.ErrorContains(t, err, "CycloneDX")

	// valid JSON but not CycloneDX
	notcdx := dir + "/notcdx.json"
	require.NoError(t, os.WriteFile(notcdx, []byte(`{"bomFormat":"SPDX"}`), 0o600))
	_, err = ParseCycloneDX(notcdx, 0)
	assert.ErrorContains(t, err, "unsupported BOM format")

	// CycloneDX with no vulnerabilities -> empty result, no error
	novulns := dir + "/novulns.json"
	require.NoError(t, os.WriteFile(novulns, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`), 0o600))
	res, err := ParseCycloneDX(novulns, 0)
	require.NoError(t, err)
	assert.Empty(t, res.Advisories)
}

func TestParseCycloneDX_AliasesFromReferencesAndURLs(t *testing.T) {
	dir := t.TempDir()
	sbom := `{
      "bomFormat": "CycloneDX",
      "specVersion": "1.6",
      "components": [
        {"bom-ref": "pkg:npm/lodash@4.17.20", "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"}
      ],
      "vulnerabilities": [
        {
          "id": "CVE-2021-1",
          "references": [{"id": "GHSA-aaaa-bbbb-cccc"}, {"id": "CVE-2021-1"}],
          "advisories": [{"url": "https://github.com/advisories/GHSA-dddd-eeee-ffff"}],
          "ratings": [{"severity": "high"}],
          "affects": [{"ref": "pkg:npm/lodash@4.17.20", "versions": [{"version": "4.17.20", "status": "affected"}]}]
        }
      ]
    }`
	path := dir + "/sbom.json"
	require.NoError(t, os.WriteFile(path, []byte(sbom), 0o600))

	res, err := ParseCycloneDX(path, 0)
	require.NoError(t, err)
	require.Len(t, res.Advisories, 1)
	aliases := res.Advisories[0].Aliases
	assert.Contains(t, aliases, "GHSA-aaaa-bbbb-cccc")
	assert.Contains(t, aliases, "GHSA-dddd-eeee-ffff")
	assert.NotContains(t, aliases, "CVE-2021-1", "self id is not an alias")
}

// TestParseCycloneDX_SeverityAndEcosystemEdges covers the unmapped-input paths:
// a vulnerability with no ratings yields unknown severity; a rating severity
// outside the known set also collapses to unknown; an affects ref that matches
// no component is dropped; and a PURL with an unlisted ecosystem keeps its raw
// (lowercased) type.
func TestParseCycloneDX_SeverityAndEcosystemEdges(t *testing.T) {
	dir := t.TempDir()
	doc := `{
      "bomFormat": "CycloneDX",
      "specVersion": "1.6",
      "components": [
        {"bom-ref": "c1", "name": "foo", "version": "1.0.0", "purl": "pkg:weirdeco/foo@1.0.0"}
      ],
      "vulnerabilities": [
        {"id": "CVE-NORATING", "affects": [{"ref": "c1"}]},
        {"id": "CVE-DANGLING", "ratings": [{"severity": "high"}], "affects": [{"ref": "does-not-exist"}]},
        {"id": "CVE-NONE", "ratings": [{"severity": "none"}], "affects": [{"ref": "c1"}]}
      ]
    }`
	path := dir + "/sbom.json"
	require.NoError(t, os.WriteFile(path, []byte(doc), 0o600))

	res, err := ParseCycloneDX(path, 0)
	require.NoError(t, err)

	byID := map[string]int{}
	for i, adv := range res.Advisories {
		byID[adv.ID] = i
	}

	norating := res.Advisories[byID["CVE-NORATING"]]
	assert.Equal(t, "Unknown", norating.Severity.Level, "no ratings -> unknown severity")
	require.Len(t, norating.Occurrences, 1)
	assert.Equal(t, "weirdeco", norating.Occurrences[0].Ecosystem, "unlisted ecosystem kept as raw lowercase")

	none := res.Advisories[byID["CVE-NONE"]]
	assert.Equal(t, "Unknown", none.Severity.Level, "unmapped rating severity -> unknown")

	dangling := res.Advisories[byID["CVE-DANGLING"]]
	assert.Empty(t, dangling.Occurrences, "affects ref with no matching component is dropped")
}
