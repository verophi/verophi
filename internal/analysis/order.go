package analysis

import (
	"sort"

	"github.com/verophi/verophi/pkg/model"
)

// orderResult applies deterministic total ordering to all collections.
func orderResult(result *model.AnalysisResult) {
	// ChangeRequests: ImpactScore desc, MergeEfficiency desc (null last), Number asc
	sort.SliceStable(result.ChangeRequests, func(i, j int) bool {
		a, b := result.ChangeRequests[i], result.ChangeRequests[j]
		if a.ImpactScore != b.ImpactScore {
			return a.ImpactScore > b.ImpactScore
		}
		aEff := effOrNeg(a.MergeEfficiency)
		bEff := effOrNeg(b.MergeEfficiency)
		if aEff != bEff {
			return aEff > bEff
		}
		return a.Number < b.Number
	})

	for ri := range result.ChangeRequests {
		cr := &result.ChangeRequests[ri]
		orderAssessments(cr.Assessments)
		for ai := range cr.Assessments {
			orderMatches(cr.Assessments[ai].AdvisoryMatches)
		}
		sort.Strings(cr.Labels)
	}

	// UncorrelatedAdvisories: Weight desc, ID asc
	sort.SliceStable(result.UncorrelatedAdvisories, func(i, j int) bool {
		a, b := result.UncorrelatedAdvisories[i], result.UncorrelatedAdvisories[j]
		if a.Severity.Weight != b.Severity.Weight {
			return a.Severity.Weight > b.Severity.Weight
		}
		return a.ID < b.ID
	})

	for ai := range result.UncorrelatedAdvisories {
		adv := &result.UncorrelatedAdvisories[ai]
		sort.Strings(adv.Aliases)
	}
}

func orderAssessments(assessments []model.ChangeAssessment) {
	sort.SliceStable(assessments, func(i, j int) bool {
		a, b := assessments[i], assessments[j]
		if a.ImpactScore != b.ImpactScore {
			return a.ImpactScore > b.ImpactScore
		}
		return a.Change.DependencyName < b.Change.DependencyName
	})
}

func orderMatches(matches []model.AdvisoryMatch) {
	sort.SliceStable(matches, func(i, j int) bool {
		a, b := matches[i], matches[j]
		if a.Advisory.Severity.Weight != b.Advisory.Severity.Weight {
			return a.Advisory.Severity.Weight > b.Advisory.Severity.Weight
		}
		if a.Advisory.ID != b.Advisory.ID {
			return a.Advisory.ID < b.Advisory.ID
		}
		if a.Occurrence.PURL != b.Occurrence.PURL {
			return a.Occurrence.PURL < b.Occurrence.PURL
		}
		return a.Occurrence.BOMRef < b.Occurrence.BOMRef
	})
}

func effOrNeg(p *float64) float64 {
	if p == nil {
		return -1 // null sorts last (below any positive efficiency)
	}
	return *p
}
