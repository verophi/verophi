package model

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnalysisResult_RoundTrip(t *testing.T) {
	reducible := 42.0
	eff := 8.3

	original := AnalysisResult{
		SchemaVersion: SchemaVersion,
		Correlation: Correlation{
			Status:     CorrelationComplete,
			Platform:   "gitlab",
			Repository: "g/p",
		},
		AdvisorySummary: AdvisorySummary{
			Total: 5, Correlated: 3, Uncorrelated: 2,
			SeverityCounts: SeverityCounts{Critical: 1, High: 2, Medium: 1, Low: 1},
		},
		TotalImpactScore:     60,
		ReducibleImpactScore: &reducible,
		ChangeRequests: []ChangeRequest{
			{
				Number:         70,
				URL:            "https://gitlab.com/g/p/-/merge_requests/70",
				Title:          "update deps",
				Platform:       "gitlab",
				AgeDays:        5,
				Labels:         []string{"renovate"},
				Status:         StatusMatched,
				RiskTier:       ChangeMajor,
				HasUnknownRisk: false,
				SplitCandidate: &SplitCandidate{
					DependencyName:  "axios",
					ImpactScore:     20,
					ShareOfRequest:  0.8,
					RiskTier:        ChangeMinor,
					MergeEfficiency: 10.0,
				},
				Stale:           false,
				ImpactScore:     25,
				MergeEfficiency: &eff,
				Fixes:           FixSummary{Total: 7, SeverityCounts: SeverityCounts{Critical: 1, High: 3, Medium: 2, Low: 1}},
				Assessments: []ChangeAssessment{
					{
						Change: Change{
							DependencyName: "axios",
							CurrentVersion: "0.21.1",
							TargetVersion:  "1.6.0",
							ChangeType:     ChangeMinor,
						},
						AdvisoryMatches: []AdvisoryMatch{
							{
								// Aliases, CVSS (on AdvisoryRef) and Confidence are
								// json:"-" and do not survive serialization, so they are
								// left at their zero values here.
								Advisory: AdvisoryRef{
									ID:       "CVE-2023-45857",
									Severity: SeverityCritical,
								},
								Occurrence: Occurrence{
									BOMRef:          "pkg:npm/axios@0.21.1",
									PURL:            "pkg:npm/axios@0.21.1",
									DependencyName:  "axios",
									Ecosystem:       "npm",
									AffectedVersion: "0.21.1",
									FixVersion:      "0.21.2",
								},
							},
						},
						ImpactScore: 20,
					},
				},
			},
		},
		UncorrelatedAdvisories: []Advisory{
			{
				ID:             "CVE-2023-1111",
				Aliases:        []string{},
				Severity:       SeverityCritical,
				Recommendation: "Upgrade openssl to version 1.1.1t",
				Occurrences: []Occurrence{
					{
						BOMRef:          "pkg:generic/openssl@1.1.1",
						PURL:            "pkg:generic/openssl@1.1.1",
						DependencyName:  "openssl",
						Ecosystem:       "generic",
						AffectedVersion: "1.1.1",
						FixVersion:      "1.1.1t",
					},
				},
				AddressedOccurrences: 0,
			},
		},
	}

	original.Normalize()

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded AnalysisResult
	require.NoError(t, json.Unmarshal(data, &decoded))
	decoded.Normalize()

	assert.Equal(t, original, decoded)
}

// TestJSON_OmitsInternalFields locks the contract decision that computed-but-
// internal fields are not exported: confidence, advisory aliases and cvss, and
// the change ecosystem/purl must never appear in the JSON, even when populated
// in memory. They are reserved for Phase 2 and must not imply they feed scoring.
func TestJSON_OmitsInternalFields(t *testing.T) {
	r := AnalysisResult{
		SchemaVersion: SchemaVersion,
		ChangeRequests: []ChangeRequest{{
			Number: 1, Status: StatusMatched,
			Assessments: []ChangeAssessment{{
				Change: Change{DependencyName: "axios", TargetVersion: "1.6.0", ChangeType: ChangeMinor},
				AdvisoryMatches: []AdvisoryMatch{{
					Advisory:   AdvisoryRef{ID: "CVE-1", Aliases: []string{"GHSA-x"}, Severity: SeverityHigh, CVSS: 7.5},
					Occurrence: Occurrence{PURL: "pkg:npm/axios@0.21.1", DependencyName: "axios"},
					Confidence: ConfidenceHigh,
				}},
			}},
		}},
		UncorrelatedAdvisories: []Advisory{
			{ID: "CVE-2", Aliases: []string{"GHSA-y"}, Severity: SeverityHigh, CVSS: 8.1},
		},
	}
	r.Normalize()
	data, err := json.Marshal(r)
	require.NoError(t, err)
	out := string(data)

	for _, key := range []string{`"confidence"`, `"aliases"`, `"cvss"`, `"ranges"`} {
		assert.NotContains(t, out, key, "internal field %s must not be serialized", key)
	}
	// the change object itself must not carry ecosystem/purl (the occurrence's
	// ecosystem/purl are legitimate and stay)
	changeJSON, err := json.Marshal(r.ChangeRequests[0].Assessments[0].Change)
	require.NoError(t, err)
	assert.NotContains(t, string(changeJSON), `"ecosystem"`, "change must not serialize ecosystem")
	assert.NotContains(t, string(changeJSON), `"purl"`, "change must not serialize purl")
}
