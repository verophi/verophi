package analysis

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/verophi/verophi/pkg/model"
	"pgregory.net/rapid"
)

func makeTestResult() (*model.SBOMResult, []model.ChangeRequest) {
	sbom := &model.SBOMResult{
		Advisories: []model.Advisory{
			{
				ID: "CVE-1", Severity: model.SeverityCritical,
				Recommendation: "Upgrade lodash to version 4.17.21",
				Occurrences: []model.Occurrence{
					{BOMRef: "pkg:npm/lodash@4.17.20", PURL: "pkg:npm/lodash@4.17.20",
						DependencyName: "lodash", Ecosystem: "npm", AffectedVersion: "4.17.20"},
				},
			},
			{
				ID: "CVE-2", Severity: model.SeverityHigh,
				Recommendation: "Upgrade express to version 4.19.2",
				Occurrences: []model.Occurrence{
					{BOMRef: "pkg:npm/express@4.17.1", PURL: "pkg:npm/express@4.17.1",
						DependencyName: "express", Ecosystem: "npm", AffectedVersion: "4.17.1"},
				},
			},
		},
	}
	requests := []model.ChangeRequest{
		{
			Number: 1, Status: model.StatusParsed,
			Assessments: []model.ChangeAssessment{
				{Change: model.Change{
					DependencyName: "lodash", TargetVersion: "4.17.21",
					ChangeType: model.ChangePatch,
				}},
				{Change: model.Change{
					DependencyName: "express", TargetVersion: "4.19.2",
					ChangeType: model.ChangeMinor,
				}},
			},
		},
	}
	return sbom, requests
}

// genPkg is a generated package: an affected version, a strictly-greater fix
// version, and an optional advisory that recommends the fix.
type genPkg struct {
	name, ecosystem, affected, fix string
	advisory                       *model.Advisory
}

var (
	genEcosystems = []string{"npm", "pip", "gem", "maven", "go"}
	genSeverities = []model.Severity{
		model.SeverityCritical, model.SeverityHigh, model.SeverityMedium,
		model.SeverityLow, model.SeverityUnknown,
	}
	genChangeTypes = []model.ChangeType{
		model.ChangePatch, model.ChangeMinor, model.ChangeMajor, model.ChangePin,
		model.ChangeRollback, model.ChangeDigest, model.ChangeReplacement, model.ChangeUnknown,
	}
)

// genInput draws a randomized, well-formed analysis input so the property tests
// explore the input space (varied severities, change-type risks, occurrence
// counts, match vs no-match) instead of re-checking one hand-built fixture.
func genInput(t *rapid.T) (*model.SBOMResult, []model.ChangeRequest) {
	pkgs := genPackages(t)
	return &model.SBOMResult{Advisories: advisoriesOf(pkgs)}, genRequests(t, pkgs)
}

func genPackages(t *rapid.T) []genPkg {
	pkgs := make([]genPkg, rapid.IntRange(1, 6).Draw(t, "packages"))
	for i := range pkgs {
		major := rapid.IntRange(0, 5).Draw(t, "affectedMajor")
		p := genPkg{
			name:      fmt.Sprintf("pkg%d", i),
			ecosystem: rapid.SampledFrom(genEcosystems).Draw(t, "ecosystem"),
			affected: fmt.Sprintf("%d.%d.%d", major,
				rapid.IntRange(0, 9).Draw(t, "affectedMinor"),
				rapid.IntRange(0, 9).Draw(t, "affectedPatch")),
			fix: fmt.Sprintf("%d.0.0", major+1), // strictly greater than affected
		}
		if rapid.Bool().Draw(t, "hasAdvisory") {
			p.advisory = advisoryFor(i, p, rapid.SampledFrom(genSeverities).Draw(t, "severity"))
		}
		pkgs[i] = p
	}
	return pkgs
}

func advisoryFor(i int, p genPkg, sev model.Severity) *model.Advisory {
	purl := fmt.Sprintf("pkg:%s/%s@%s", p.ecosystem, p.name, p.affected)
	return &model.Advisory{
		ID:             fmt.Sprintf("CVE-%d", i),
		Severity:       sev,
		Recommendation: fmt.Sprintf("Upgrade %s to version %s", p.name, p.fix),
		Occurrences: []model.Occurrence{{
			BOMRef: purl, PURL: purl, DependencyName: p.name,
			Ecosystem: p.ecosystem, AffectedVersion: p.affected,
		}},
	}
}

func advisoriesOf(pkgs []genPkg) []model.Advisory {
	var advs []model.Advisory
	for _, p := range pkgs {
		if p.advisory != nil {
			advs = append(advs, *p.advisory)
		}
	}
	return advs
}

func genRequests(t *rapid.T, pkgs []genPkg) []model.ChangeRequest {
	n := rapid.IntRange(1, 5).Draw(t, "requests")
	requests := make([]model.ChangeRequest, 0, n)
	for j := 0; j < n; j++ {
		requests = append(requests, model.ChangeRequest{
			Number:      j + 1,
			Status:      model.StatusParsed,
			Assessments: genAssessments(t, pkgs),
		})
	}
	return requests
}

func genAssessments(t *rapid.T, pkgs []genPkg) []model.ChangeAssessment {
	n := rapid.IntRange(1, 3).Draw(t, "assessments")
	out := make([]model.ChangeAssessment, 0, n)
	for k := 0; k < n; k++ {
		p := pkgs[rapid.IntRange(0, len(pkgs)-1).Draw(t, "package")]
		target := p.affected // falls short of the fix -> no match
		if rapid.Bool().Draw(t, "reachesFix") {
			target = p.fix
		}
		out = append(out, model.ChangeAssessment{
			Change: model.Change{
				DependencyName: p.name,
				CurrentVersion: p.affected,
				TargetVersion:  target,
				ChangeType:     rapid.SampledFrom(genChangeTypes).Draw(t, "changeType"),
			},
		})
	}
	return out
}

func TestAnalyze_BasicScoring(t *testing.T) {
	sbom, requests := makeTestResult()
	corr := model.Correlation{Status: model.CorrelationComplete, Platform: "gitlab", Repository: "g/p"}
	result := Analyze(sbom, requests, corr, Options{Now: time.Now(), StaleDays: 14})

	assert.Equal(t, model.SchemaVersion, result.SchemaVersion)
	assert.Equal(t, 2, result.AdvisorySummary.Total)
	assert.Equal(t, 2, result.AdvisorySummary.Correlated)
	assert.Equal(t, 0, result.AdvisorySummary.Uncorrelated)
	assert.Equal(t, 12.0, result.TotalImpactScore) // 8 + 4
	assert.NotNil(t, result.ReducibleImpactScore)
	assert.Equal(t, 12.0, *result.ReducibleImpactScore)
	assert.Equal(t, 12.0, result.ChangeRequests[0].ImpactScore) // fully addresses both
	assert.Equal(t, model.StatusMatched, result.ChangeRequests[0].Status)

	// Per-CR fixed breakdown: lodash (critical) + express (high) -> 2 CVEs, C:1 H:1.
	f := result.ChangeRequests[0].Fixes
	assert.Equal(t, 2, f.Total)
	assert.Equal(t, 1, f.Critical)
	assert.Equal(t, 1, f.High)
	assert.Equal(t, 0, f.Medium)
	assert.Equal(t, 0, f.Low)
}

// Property: the severity-weighted sum of a request's Fixes equals its CR-VIS.
// This guards the contract that the human-output "fixes N CVEs C:H:M:L" line and
// the VIS number tell the same story.
func TestProperty_FixesWeightedSumEqualsCRVIS(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		sbom, requests := genInput(t)
		corr := model.Correlation{Status: model.CorrelationComplete}
		result := Analyze(sbom, requests, corr, Options{Now: time.Now(), StaleDays: 14})
		for _, cr := range result.ChangeRequests {
			f := cr.Fixes
			weighted := float64(8*f.Critical + 4*f.High + 2*f.Medium + 1*f.Low)
			if weighted != cr.ImpactScore {
				t.Fatalf("CR %d: weighted fixes %.0f != CR-VIS %.0f", cr.Number, weighted, cr.ImpactScore)
			}
			if f.Total < f.Critical+f.High+f.Medium+f.Low {
				t.Fatalf("CR %d: Fixes.Total %d < bucket sum", cr.Number, f.Total)
			}
		}
	})
}

// Property 1: ReducibleImpactScore <= TotalImpactScore
func TestProperty1_ReducibleBoundedByTotal(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		sbom, requests := genInput(t)
		corr := model.Correlation{Status: model.CorrelationComplete}
		result := Analyze(sbom, requests, corr, Options{Now: time.Now(), StaleDays: 14})
		if result.ReducibleImpactScore != nil {
			if *result.ReducibleImpactScore > result.TotalImpactScore {
				t.Fatalf("reducible %f > total %f", *result.ReducibleImpactScore, result.TotalImpactScore)
			}
		}
	})
}

// Property 2: Summary partition (Correlated + Uncorrelated == Total)
func TestProperty2_SummaryPartition(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		sbom, requests := genInput(t)
		corr := model.Correlation{Status: model.CorrelationComplete}
		result := Analyze(sbom, requests, corr, Options{Now: time.Now(), StaleDays: 14})
		sum := result.AdvisorySummary.Correlated + result.AdvisorySummary.Uncorrelated
		if sum != result.AdvisorySummary.Total {
			t.Fatalf("correlated %d + uncorrelated %d != total %d",
				result.AdvisorySummary.Correlated,
				result.AdvisorySummary.Uncorrelated,
				result.AdvisorySummary.Total)
		}
	})
}

// Property 3: Non-negative impact
func TestProperty3_NonNegativeImpact(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		sbom, requests := genInput(t)
		corr := model.Correlation{Status: model.CorrelationComplete}
		result := Analyze(sbom, requests, corr, Options{Now: time.Now(), StaleDays: 14})
		for _, cr := range result.ChangeRequests {
			if cr.ImpactScore < 0 {
				t.Fatalf("CR-VIS %f < 0", cr.ImpactScore)
			}
			for _, a := range cr.Assessments {
				if a.ImpactScore < 0 {
					t.Fatalf("Change-VIS %f < 0", a.ImpactScore)
				}
			}
		}
	})
}

// Property 4: Merge efficiency formula
func TestProperty4_MergeEfficiencyFormula(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		sbom, requests := genInput(t)
		corr := model.Correlation{Status: model.CorrelationComplete}
		result := Analyze(sbom, requests, corr, Options{Now: time.Now(), StaleDays: 14})
		for _, cr := range result.ChangeRequests {
			if cr.HasUnknownRisk {
				if cr.MergeEfficiency != nil {
					t.Fatalf("unknown risk should have nil MergeEfficiency")
				}
			} else if cr.RiskTier.Risk > 0 && cr.MergeEfficiency != nil {
				expected := cr.ImpactScore / float64(cr.RiskTier.Risk)
				if *cr.MergeEfficiency != expected {
					t.Fatalf("VME %f != VIS %f / Risk %d", *cr.MergeEfficiency, cr.ImpactScore, cr.RiskTier.Risk)
				}
			}
		}
	})
}

// Property 6: Within-request dedup (CR-VIS <= sum of child Change-VIS)
func TestProperty6_DedupNeverInflates(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		sbom, requests := genInput(t)
		corr := model.Correlation{Status: model.CorrelationComplete}
		result := Analyze(sbom, requests, corr, Options{Now: time.Now(), StaleDays: 14})
		for _, cr := range result.ChangeRequests {
			var sumChildVIS float64
			for _, a := range cr.Assessments {
				sumChildVIS += a.ImpactScore
			}
			if cr.ImpactScore > sumChildVIS {
				t.Fatalf("CR-VIS %f > sum child VIS %f", cr.ImpactScore, sumChildVIS)
			}
		}
	})
}

// Property 9: Risk tier is the max
func TestProperty9_RiskTierIsMax(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		sbom, requests := genInput(t)
		corr := model.Correlation{Status: model.CorrelationComplete}
		result := Analyze(sbom, requests, corr, Options{Now: time.Now(), StaleDays: 14})
		for _, cr := range result.ChangeRequests {
			if cr.Status == model.StatusUnparsed {
				continue
			}
			expected := model.ComputeRiskTier(cr.Assessments)
			if cr.RiskTier != expected {
				t.Fatalf("RiskTier %v != expected %v", cr.RiskTier, expected)
			}
		}
	})
}

func TestAnalyze_ReducibleNilWhenNotRun(t *testing.T) {
	sbom, requests := makeTestResult()
	corr := model.Correlation{Status: model.CorrelationNotRun}
	result := Analyze(sbom, requests, corr, Options{Now: time.Now(), StaleDays: 14})
	assert.Nil(t, result.ReducibleImpactScore)
}

// TestAnalyze_SharedOccurrenceNoOverclaim guards against crediting an advisory
// just because another advisory on the SAME component occurrence was fixed.
// log4j-core@2.14.1 carries two CVEs with different fix versions; a change to
// 2.17.1 fixes the older one (fix 2.15.0) but not the newer one (fix 2.25.4).
// Keying matches on the component alone (BOMRef+PURL) wrongly credited both,
// inflating reducible/correlated and dropping the unfixed advisory from output.
func TestAnalyze_SharedOccurrenceNoOverclaim(t *testing.T) {
	occ := model.Occurrence{
		BOMRef:          "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
		PURL:            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
		DependencyName:  "log4j-core",
		Ecosystem:       "maven",
		AffectedVersion: "2.14.1",
	}
	sbom := &model.SBOMResult{
		Advisories: []model.Advisory{
			{
				ID: "CVE-OLD", Severity: model.SeverityCritical,
				Recommendation: "Upgrade org.apache.logging.log4j:log4j-core to version 2.15.0",
				Occurrences:    []model.Occurrence{occ},
			},
			{
				ID: "CVE-NEW", Severity: model.SeverityHigh,
				Recommendation: "Upgrade org.apache.logging.log4j:log4j-core to version 2.25.4",
				Occurrences:    []model.Occurrence{occ},
			},
		},
	}
	requests := []model.ChangeRequest{
		{
			Number: 81, Status: model.StatusParsed,
			Assessments: []model.ChangeAssessment{
				{Change: model.Change{
					DependencyName: "org.apache.logging.log4j:log4j-core",
					TargetVersion:  "2.17.1",
					ChangeType:     model.ChangeMinor,
				}},
			},
		},
	}

	corr := model.Correlation{Status: model.CorrelationComplete, Platform: "gitlab", Repository: "g/p"}
	result := Analyze(sbom, requests, corr, Options{Now: time.Now(), StaleDays: 14})

	// Only CVE-OLD is actually fixed by 2.17.1.
	assert.Equal(t, 1, result.AdvisorySummary.Correlated, "only the fixed advisory must correlate")
	assert.Equal(t, 1, result.AdvisorySummary.Uncorrelated, "the advisory needing 2.25.4 must stay uncorrelated")
	assert.NotNil(t, result.ReducibleImpactScore)
	assert.Equal(t, 8.0, *result.ReducibleImpactScore, "reducible counts only CVE-OLD (critical=8), not CVE-NEW")

	// CVE-NEW must still be visible as uncorrelated, not silently dropped.
	var newFound bool
	for _, adv := range result.UncorrelatedAdvisories {
		if adv.ID == "CVE-NEW" {
			newFound = true
			assert.Equal(t, 0, adv.AddressedOccurrences, "CVE-NEW has no addressed occurrence")
		}
	}
	assert.True(t, newFound, "CVE-NEW must appear in uncorrelatedAdvisories")

	// The request fully addresses only CVE-OLD -> CR-VIS = 8.
	assert.Equal(t, 8.0, result.ChangeRequests[0].ImpactScore)
}

// TestOrderResult_DeterministicTotalOrdering exercises every ordering key (R11):
// change requests by VIS desc, VME desc (null last), number asc; assessments by
// VIS desc, name asc; advisory matches by weight desc, id asc, PURL asc, BOMRef
// asc; uncorrelated by weight desc, id asc; and secondary lists (labels,
// aliases) ascending.
func TestOrderResult_DeterministicTotalOrdering(t *testing.T) {
	eff2, eff5 := 2.0, 5.0
	result := &model.AnalysisResult{
		ChangeRequests: []model.ChangeRequest{
			// same VIS 10: one with VME nil (null last), two with VME 2 vs 5, plus number tiebreak
			{Number: 9, ImpactScore: 10, MergeEfficiency: nil, Labels: []string{"z", "a"}},
			{Number: 3, ImpactScore: 10, MergeEfficiency: &eff2},
			{Number: 7, ImpactScore: 10, MergeEfficiency: &eff5},
			{Number: 2, ImpactScore: 20, MergeEfficiency: &eff2,
				Assessments: []model.ChangeAssessment{
					{Change: model.Change{DependencyName: "b"}, ImpactScore: 4},
					{Change: model.Change{DependencyName: "a"}, ImpactScore: 4},
					{Change: model.Change{DependencyName: "c"}, ImpactScore: 8,
						AdvisoryMatches: []model.AdvisoryMatch{
							{Advisory: model.AdvisoryRef{ID: "CVE-2", Severity: model.SeverityHigh}, Occurrence: model.Occurrence{PURL: "z", BOMRef: "b2"}},
							{Advisory: model.AdvisoryRef{ID: "CVE-1", Severity: model.SeverityCritical}, Occurrence: model.Occurrence{PURL: "a", BOMRef: "b1"}},
							{Advisory: model.AdvisoryRef{ID: "CVE-1", Severity: model.SeverityCritical}, Occurrence: model.Occurrence{PURL: "a", BOMRef: "b0"}},
						}},
				}},
		},
		UncorrelatedAdvisories: []model.Advisory{
			{ID: "CVE-B", Severity: model.SeverityMedium, Aliases: []string{"GHSA-z", "GHSA-a"}},
			{ID: "CVE-A", Severity: model.SeverityCritical},
			{ID: "CVE-C", Severity: model.SeverityMedium},
		},
	}

	orderResult(result)

	// ChangeRequests: VIS 20 first; then VIS 10 group ordered by VME desc (5,2,nil), number breaks nothing here
	assert.Equal(t, []int{2, 7, 3, 9}, []int{
		result.ChangeRequests[0].Number, result.ChangeRequests[1].Number,
		result.ChangeRequests[2].Number, result.ChangeRequests[3].Number,
	})
	// Labels sorted ascending
	assert.Equal(t, []string{"a", "z"}, result.ChangeRequests[3].Labels)

	// Assessments of CR #2: VIS desc (c=8 first), then name asc (a before b)
	cr2 := result.ChangeRequests[0]
	assert.Equal(t, "c", cr2.Assessments[0].Change.DependencyName)
	assert.Equal(t, "a", cr2.Assessments[1].Change.DependencyName)
	assert.Equal(t, "b", cr2.Assessments[2].Change.DependencyName)

	// Matches of assessment c: weight desc (CVE-1 critical first), then id, PURL, BOMRef asc
	m := cr2.Assessments[0].AdvisoryMatches
	assert.Equal(t, "CVE-1", m[0].Advisory.ID)
	assert.Equal(t, "b0", m[0].Occurrence.BOMRef) // BOMRef asc among equal id/PURL
	assert.Equal(t, "b1", m[1].Occurrence.BOMRef)
	assert.Equal(t, "CVE-2", m[2].Advisory.ID)

	// UncorrelatedAdvisories: weight desc (critical first), then id asc among equal weight
	assert.Equal(t, "CVE-A", result.UncorrelatedAdvisories[0].ID)
	assert.Equal(t, "CVE-B", result.UncorrelatedAdvisories[1].ID)
	assert.Equal(t, "CVE-C", result.UncorrelatedAdvisories[2].ID)
	// Aliases sorted ascending
	assert.Equal(t, []string{"GHSA-a", "GHSA-z"}, result.UncorrelatedAdvisories[1].Aliases)
}
