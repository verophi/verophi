package model

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func TestAnalysisResult_RoundTrip_NullFields(t *testing.T) {
	original := AnalysisResult{
		SchemaVersion: SchemaVersion,
		Correlation: Correlation{
			Status: CorrelationNotRun,
		},
		AdvisorySummary: AdvisorySummary{
			Total: 2, Uncorrelated: 2, SeverityCounts: SeverityCounts{High: 1, Medium: 1},
		},
		TotalImpactScore:       6,
		ReducibleImpactScore:   nil,
		ChangeRequests:         []ChangeRequest{},
		UncorrelatedAdvisories: []Advisory{},
	}
	original.Normalize()

	data, err := json.Marshal(original)
	require.NoError(t, err)

	// reducibleImpactScore should be null
	assert.Contains(t, string(data), `"reducibleImpactScore":null`)

	var decoded AnalysisResult
	require.NoError(t, json.Unmarshal(data, &decoded))
	decoded.Normalize()

	assert.Equal(t, original, decoded)
}

func TestSeverity_MarshalUnmarshal(t *testing.T) {
	tests := []struct {
		sev      Severity
		expected string
	}{
		{SeverityCritical, `"critical"`},
		{SeverityHigh, `"high"`},
		{SeverityMedium, `"medium"`},
		{SeverityLow, `"low"`},
		{SeverityUnknown, `"unknown"`},
	}
	for _, tt := range tests {
		data, err := json.Marshal(tt.sev)
		require.NoError(t, err)
		assert.Equal(t, tt.expected, string(data))

		var decoded Severity
		require.NoError(t, json.Unmarshal(data, &decoded))
		assert.Equal(t, tt.sev, decoded)
	}
}

// Property 5: Severity monotonicity (Critical > High > Medium > Low > Unknown)
func TestProperty5_SeverityMonotonicity(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		levels := []Severity{
			SeverityCritical,
			SeverityHigh,
			SeverityMedium,
			SeverityLow,
			SeverityUnknown,
		}
		for i := 0; i < len(levels)-1; i++ {
			if levels[i].Weight <= levels[i+1].Weight {
				t.Fatalf("severity %s (weight %d) should be > %s (weight %d)",
					levels[i].Level, levels[i].Weight,
					levels[i+1].Level, levels[i+1].Weight)
			}
		}
	})
}

func TestComputeRiskTier(t *testing.T) {
	tests := []struct {
		name        string
		assessments []ChangeAssessment
		expected    ChangeType
	}{
		{
			name:        "empty assessments",
			assessments: nil,
			expected:    ChangeUnknown,
		},
		{
			name: "all risk 0",
			assessments: []ChangeAssessment{
				{Change: Change{ChangeType: ChangeDigest}},
				{Change: Change{ChangeType: ChangeReplacement}},
			},
			expected: ChangeUnknown,
		},
		{
			name: "single patch",
			assessments: []ChangeAssessment{
				{Change: Change{ChangeType: ChangePatch}},
			},
			expected: ChangePatch,
		},
		{
			name: "major wins over minor",
			assessments: []ChangeAssessment{
				{Change: Change{ChangeType: ChangeMinor}},
				{Change: Change{ChangeType: ChangeMajor}},
				{Change: Change{ChangeType: ChangePatch}},
			},
			expected: ChangeMajor,
		},
		{
			name: "tie-break: smallest name wins",
			assessments: []ChangeAssessment{
				{Change: Change{ChangeType: ChangeType{Name: "rollback", Risk: 3}}},
				{Change: Change{ChangeType: ChangeType{Name: "major", Risk: 3}}},
			},
			expected: ChangeType{Name: "major", Risk: 3},
		},
		{
			name: "risk 0 ignored, patch wins",
			assessments: []ChangeAssessment{
				{Change: Change{ChangeType: ChangeDigest}},
				{Change: Change{ChangeType: ChangePatch}},
			},
			expected: ChangePatch,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputeRiskTier(tt.assessments)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestNormalize_NilSlicesBecomEmpty(t *testing.T) {
	r := AnalysisResult{}
	r.Normalize()

	assert.NotNil(t, r.ChangeRequests)
	assert.NotNil(t, r.UncorrelatedAdvisories)
	assert.Equal(t, 0, len(r.ChangeRequests))
	assert.Equal(t, 0, len(r.UncorrelatedAdvisories))
}

func TestSeverity_UnmarshalErrors(t *testing.T) {
	var s Severity
	// non-string JSON -> decode error
	assert.Error(t, s.UnmarshalJSON([]byte(`123`)))
	// unknown level -> error
	assert.Error(t, s.UnmarshalJSON([]byte(`"bogus"`)))
}

func TestSeverityCounts_Add(t *testing.T) {
	var c SeverityCounts
	c.Add(SeverityCritical)
	c.Add(SeverityHigh)
	c.Add(SeverityHigh)
	c.Add(SeverityMedium)
	c.Add(SeverityLow)
	c.Add(SeverityUnknown) // no bucket
	assert.Equal(t, 1, c.Critical)
	assert.Equal(t, 2, c.High)
	assert.Equal(t, 1, c.Medium)
	assert.Equal(t, 1, c.Low)
}

func TestNormalize_AlreadyPopulatedIsPreserved(t *testing.T) {
	r := &AnalysisResult{
		ChangeRequests: []ChangeRequest{
			{
				Number: 1,
				Labels: []string{"renovate"},
				Assessments: []ChangeAssessment{
					{
						Change: Change{DependencyName: "lodash"},
						AdvisoryMatches: []AdvisoryMatch{
							{
								Advisory:   AdvisoryRef{ID: "CVE-1", Aliases: []string{"GHSA-x"}},
								Occurrence: Occurrence{PURL: "pkg:npm/lodash@1"},
							},
						},
					},
				},
			},
		},
		UncorrelatedAdvisories: []Advisory{
			{ID: "CVE-2", Aliases: []string{"GHSA-y"}, Occurrences: []Occurrence{{PURL: "pkg:npm/x@1"}}},
		},
	}
	r.Normalize()

	// populated slices preserved
	assert.Equal(t, []string{"renovate"}, r.ChangeRequests[0].Labels)
	assert.Len(t, r.ChangeRequests[0].Assessments[0].AdvisoryMatches, 1)
	// nested nil slices normalized to empty
	assert.NotNil(t, r.ChangeRequests[0].Assessments[0].AdvisoryMatches[0].Advisory.Aliases)
	assert.NotNil(t, r.UncorrelatedAdvisories[0].Occurrences)
	assert.NotNil(t, r.UncorrelatedAdvisories[0].Aliases)
}

func TestNormalize_PresentItemsWithNilSubslices(t *testing.T) {
	r := &AnalysisResult{
		ChangeRequests: []ChangeRequest{
			{
				Number: 1, // Labels nil, Assessments nil
			},
			{
				Number: 2,
				Assessments: []ChangeAssessment{
					{Change: Change{DependencyName: "x"}}, // AdvisoryMatches nil
				},
			},
		},
		UncorrelatedAdvisories: []Advisory{
			{ID: "CVE-1"}, // Aliases nil, Occurrences nil
		},
	}
	r.Normalize()

	assert.NotNil(t, r.ChangeRequests[0].Labels)
	assert.NotNil(t, r.ChangeRequests[0].Assessments)
	assert.NotNil(t, r.ChangeRequests[1].Assessments[0].AdvisoryMatches)
	assert.NotNil(t, r.UncorrelatedAdvisories[0].Aliases)
	assert.NotNil(t, r.UncorrelatedAdvisories[0].Occurrences)
}

// TestNormalize_AdvisoryMatchNilAliases covers the AdvisoryRef.Aliases nil->[]
// normalization inside a match, which the round-trip relies on (a nil slice
// would marshal as null and break DeepEqual against a decoded []).
func TestNormalize_AdvisoryMatchNilAliases(t *testing.T) {
	r := &AnalysisResult{
		ChangeRequests: []ChangeRequest{{
			Assessments: []ChangeAssessment{{
				AdvisoryMatches: []AdvisoryMatch{
					{Advisory: AdvisoryRef{ID: "CVE-1"}}, // Aliases nil
				},
			}},
		}},
	}
	r.Normalize()
	assert.NotNil(t, r.ChangeRequests[0].Assessments[0].AdvisoryMatches[0].Advisory.Aliases)
}
