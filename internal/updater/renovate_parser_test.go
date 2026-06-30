package updater

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/verophi/verophi/pkg/model"
)

func TestRenovateParser_ExtractChanges_FromDescription(t *testing.T) {
	desc := "| Package | Update | Change |\n" +
		"|---|---|---|\n" +
		"| [lodash](https://lodash.com) | `4.17.20` \u2192 `4.17.21` | patch |\n" +
		"| [axios](https://axios-http.com) | `0.21.1` \u2192 `1.6.0` | major |\n"

	p := RenovateParser{}
	changes, _ := p.ExtractChanges(ParserInput{Description: desc})

	assert.Len(t, changes, 2)
	assert.Equal(t, "lodash", changes[0].DependencyName)
	assert.Equal(t, "4.17.20", changes[0].CurrentVersion)
	assert.Equal(t, "4.17.21", changes[0].TargetVersion)
	assert.Equal(t, model.ChangePatch, changes[0].ChangeType)

	assert.Equal(t, "axios", changes[1].DependencyName)
	assert.Equal(t, model.ChangeMajor, changes[1].ChangeType)
}

func TestRenovateParser_ExtractChanges_FromTitle(t *testing.T) {
	p := RenovateParser{}
	changes, _ := p.ExtractChanges(ParserInput{
		Title: "Update dependency express to v4.19.2",
	})
	assert.Len(t, changes, 1)
	assert.Equal(t, "express", changes[0].DependencyName)
	assert.Equal(t, "4.19.2", changes[0].TargetVersion)
	assert.Equal(t, model.ChangeUnknown, changes[0].ChangeType) // no updateType from title
}

func TestRenovateParser_ExtractChanges_FromBranch(t *testing.T) {
	p := RenovateParser{}
	changes, _ := p.ExtractChanges(ParserInput{
		Branch: "renovate/lodash-4.17.21",
	})
	assert.Len(t, changes, 1)
	assert.Equal(t, "lodash", changes[0].DependencyName)
	assert.Equal(t, "4.17.21", changes[0].TargetVersion)
}

func TestRenovateParser_ExtractChanges_NoInput(t *testing.T) {
	p := RenovateParser{}
	changes, _ := p.ExtractChanges(ParserInput{})
	assert.Empty(t, changes)
}

func TestMapUpdateType_Extended(t *testing.T) {
	tests := []struct {
		input    string
		expected model.ChangeType
	}{
		{"major", model.ChangeMajor},
		{"minor", model.ChangeMinor},
		{"patch", model.ChangePatch},
		{"pin", model.ChangePin},
		{"pinDigest", model.ChangePinDigest},
		{"bump", model.ChangeBump},
		{"digest", model.ChangeDigest},
		{"rollback", model.ChangeRollback},
		{"replacement", model.ChangeReplacement},
		{"lockFileMaintenance", model.ChangeMaintenance},
		{"unknown_thing", model.ChangeUnknown},
		{"", model.ChangeUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := mapUpdateType(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestDescUpdateTypePattern_ExtendedTypes(t *testing.T) {
	tests := []struct {
		line     string
		expected string
	}{
		{"| bump |", "bump"},
		{"| pinDigest |", "pinDigest"},
		{"| lockFileMaintenance |", "lockFileMaintenance"},
		{"| major |", "major"},
		{"| digest |", "digest"},
	}
	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			m := descUpdateTypePattern.FindStringSubmatch(tt.line)
			assert.Len(t, m, 2)
			assert.Equal(t, tt.expected, m[1])
		})
	}
}

func TestStripVersionPrefix(t *testing.T) {
	assert.Equal(t, "", stripVersionPrefix(""))
	assert.Equal(t, "", stripVersionPrefix("   "))
	assert.Equal(t, "1.2.3", stripVersionPrefix("^1.2.3"))
	assert.Equal(t, "1.2.3", stripVersionPrefix(">= 1.2.3"))
	assert.Equal(t, "2.0.0", stripVersionPrefix("v2.0.0"))
	// no leading digit after stripping operators -> semver extraction from raw
	assert.Equal(t, "1.19", stripVersionPrefix("go1.19"))
	// nothing version-like -> returned unchanged
	assert.Equal(t, "latest", stripVersionPrefix("latest"))
}

func TestParseBranchName(t *testing.T) {
	dep, _, to := parseBranchName("renovate/lodash-4.17.21")
	assert.Equal(t, "lodash", dep)
	assert.Equal(t, "4.17.21", to)

	dep, _, to = parseBranchName("renovate/axios-4.x")
	assert.Equal(t, "axios", dep)
	assert.Equal(t, "4.0.0", to)

	dep, _, _ = parseBranchName("feature/unrelated")
	assert.Equal(t, "", dep)
}

// TestParseDescription_PlainPackageAndMisses covers the description table
// branches: an unlinked (plain) package name falls back from the linked-name
// pattern; a row whose package cell does not match either pattern is skipped;
// and a row with no parseable version transition is skipped.
func TestParseDescription_PlainPackageAndMisses(t *testing.T) {
	// unlinked package name + valid version arrow -> plain-pattern fallback
	plain, _ := parseDescription("| lodash | `4.17.20` \u2192 `4.17.21` | patch |")
	require.Len(t, plain, 1)
	assert.Equal(t, "lodash", plain[0].DependencyName)
	assert.Equal(t, "4.17.21", plain[0].TargetVersion)

	// pipe + arrow but no parseable version transition on a non-digest row ->
	// not parsed, and counted as an unparsed dependency row
	res, unparsed := parseDescription("| somepkg | not a version \u2192 also not | patch |")
	assert.Empty(t, res)
	assert.Equal(t, 1, unparsed)

	// pipe + arrow but no package cell match at all -> skipped, not counted
	res2, unparsed2 := parseDescription("|  | `1.0.0` \u2192 `2.0.0` |")
	assert.Empty(t, res2)
	assert.Equal(t, 0, unparsed2)
}

// TestParseDescription_PinDigestRow covers the digest branch (10b): a pinDigest
// row carries a SHA target ("→ `fb4cd12`"), not a semver, so the version pattern
// skips it. It must still be parsed as a pinDigest change so the dependency is
// surfaced (risk 0 / unknown) instead of silently dropped.
func TestParseDescription_PinDigestRow(t *testing.T) {
	desc := "| Package | Type | Update | Change |\n" +
		"|---|---|---|---|\n" +
		"| [json5](http://json5.org/) | dependencies | pin | [`^2.2.1` \u2192 `2.2.3`](x) |\n" +
		"| [node](https://github.com/nodejs/node) | final | pinDigest |  \u2192 `fb4cd12` |\n"
	res, unparsed := parseDescription(desc)
	require.Len(t, res, 2)
	assert.Equal(t, 0, unparsed, "the digest row is parsed, not counted as unparsed")
	assert.Equal(t, "node", res[1].DependencyName)
	assert.Equal(t, "fb4cd12", res[1].TargetVersion)
	assert.Equal(t, "pinDigest", res[1].UpdateType)

	p := RenovateParser{}
	changes, _ := p.ExtractChanges(ParserInput{Description: desc})
	require.Len(t, changes, 2)
	assert.Equal(t, model.ChangePinDigest, changes[1].ChangeType, "pinDigest is risk 0 (unknown)")
}

// TestParseDigestChange_WithFromAndTo covers a digest update that replaces an
// existing digest: both the from and to SHA tokens are captured.
func TestParseDigestChange_WithFromAndTo(t *testing.T) {
	from, to := parseDigestChange("| [img](x) | final | digest | `oldsha1` \u2192 `newsha2` |")
	assert.Equal(t, "oldsha1", from)
	assert.Equal(t, "newsha2", to)
}
