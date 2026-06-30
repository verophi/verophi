package change

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/verophi/verophi/internal/platform"
	"github.com/verophi/verophi/internal/updater"
	"github.com/verophi/verophi/pkg/model"
)

func TestBuild_GroupedRequest(t *testing.T) {
	inputs := []platform.ChangeRequestRaw{
		{
			Number:      70,
			URL:         "https://gitlab.com/g/p/-/merge_requests/70",
			Title:       "update http-client-group",
			Platform:    "gitlab",
			Labels:      []string{"renovate"},
			CreatedAt:   time.Now(),
			Description: "| Package | Update | Change |\n|---|---|---|\n| [axios](https://x) | `0.21.1` \u2192 `1.6.0` | major |\n| [got](https://x) | `11.0.0` \u2192 `12.0.0` | major |\n",
		},
	}

	parser := updater.RenovateParser{}
	results := Build(inputs, parser)

	assert.Len(t, results, 1)
	cr := results[0]
	assert.Equal(t, 70, cr.Number)
	assert.Equal(t, model.StatusParsed, cr.Status)
	assert.Len(t, cr.Assessments, 2)
	assert.Equal(t, "axios", cr.Assessments[0].Change.DependencyName)
	assert.Equal(t, model.ChangeMajor, cr.Assessments[0].Change.ChangeType)
}

func TestBuild_UnparsedRequest(t *testing.T) {
	inputs := []platform.ChangeRequestRaw{
		{
			Number:   61,
			Title:    "some random MR",
			Platform: "gitlab",
		},
	}

	parser := updater.RenovateParser{}
	results := Build(inputs, parser)

	assert.Len(t, results, 1)
	assert.Equal(t, model.StatusUnparsed, results[0].Status)
	assert.Empty(t, results[0].Assessments)
}

// TestBuild_LayoutBWithoutUpdateColumn guards the version-diff fallback. Some
// Renovate tables carry Age/Confidence badge columns instead of an Update
// column, so the parser returns no updateType. The aggregate must then classify
// from the version transition rather than leaving the change unknown (the
// redesign dropped this and every such request collapsed to unknown risk).
func TestBuild_LayoutBWithoutUpdateColumn(t *testing.T) {
	desc := "| Package | Change | [Age](https://docs.renovatebot.com/merge-confidence/) | [Confidence](https://docs.renovatebot.com/merge-confidence/) |\n" +
		"|---|---|---|---|\n" +
		"| [Pillow](https://github.com/python-pillow/Pillow) | `==9.0.0` \u2192 `==10.2.0` | ![age](https://x) | ![confidence](https://x) |\n"

	inputs := []platform.ChangeRequestRaw{{
		Number:      91,
		Title:       "chore(deps): update dependency pillow to v10",
		Platform:    "gitlab",
		Description: desc,
	}}

	results := Build(inputs, updater.RenovateParser{})

	assert.Len(t, results, 1)
	cr := results[0]
	assert.Equal(t, model.StatusParsed, cr.Status)
	assert.Len(t, cr.Assessments, 1)
	assert.Equal(t, "Pillow", cr.Assessments[0].Change.DependencyName)
	assert.Equal(t, model.ChangeMajor, cr.Assessments[0].Change.ChangeType,
		"9.0.0 -> 10.2.0 must classify as major via version-diff fallback, not unknown")
}

func TestClassifyFromVersions(t *testing.T) {
	tests := []struct {
		name    string
		current string
		target  string
		want    model.ChangeType
	}{
		{"major bump", "9.0.0", "10.2.0", model.ChangeMajor},
		{"minor bump", "5.3.1", "5.4.1", model.ChangeMinor},
		{"patch bump", "4.17.20", "4.17.21", model.ChangePatch},
		{"ruby four-segment patch", "6.1.4", "6.1.7.8", model.ChangePatch},
		{"zero-major minor", "0.21.0", "0.40.0", model.ChangeMinor},
		{"empty current", "", "1.0.0", model.ChangeUnknown},
		{"empty target", "1.0.0", "", model.ChangeUnknown},
		{"unparseable current", "20-alpine", "24-alpine", model.ChangeUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, classifyFromVersions(tt.current, tt.target))
		})
	}
}

// TestClassifyFromVersions_UnparseableTarget covers the branch where the current
// version parses but the target does not (e.g. a tag-style target), which must
// stay unknown rather than guess.
func TestClassifyFromVersions_UnparseableTarget(t *testing.T) {
	assert.Equal(t, model.ChangeUnknown, classifyFromVersions("1.0.0", "latest"))
}
