package analysis

import (
	"github.com/verophi/verophi/pkg/model"
)

// computeFlags computes HasUnknownRisk, RiskTier, MergeEfficiency,
// SplitCandidate, and Stale for each change request. staleDays is the age
// threshold above which a request is marked stale; <= 0 disables the mark.
func computeFlags(requests []model.ChangeRequest, staleDays int) {
	for ri := range requests {
		r := &requests[ri]
		if r.Status == model.StatusUnparsed {
			continue
		}

		r.RiskTier = model.ComputeRiskTier(r.Assessments)
		r.HasUnknownRisk = hasUnknownRisk(r.Assessments)

		if !r.HasUnknownRisk && r.RiskTier.Risk > 0 {
			r.MergeEfficiency = new(r.ImpactScore / float64(r.RiskTier.Risk))
		} else {
			r.MergeEfficiency = nil
		}

		r.SplitCandidate = computeSplitCandidate(r)
		r.Stale = staleDays > 0 && r.AgeDays > staleDays
	}
}

func hasUnknownRisk(assessments []model.ChangeAssessment) bool {
	for _, a := range assessments {
		if a.Change.ChangeType.Risk == 0 {
			return true
		}
	}
	return false
}

// computeSplitCandidate finds the lower-risk child worth cherry-picking: a
// single dependency in a grouped request that carries most of the security
// value at lower merge risk than the whole group, so a maintainer can merge it
// alone first.
func computeSplitCandidate(r *model.ChangeRequest) *model.SplitCandidate {
	// Requires computable CR-VME and CR-VIS > 0
	if r.HasUnknownRisk || r.MergeEfficiency == nil || r.ImpactScore <= 0 {
		return nil
	}
	crVME := *r.MergeEfficiency

	var best *model.SplitCandidate
	for _, a := range r.Assessments {
		ct := a.Change.ChangeType

		// Skip children that are not lower-risk than the group, risk-0, or carry
		// too little value to be worth splitting out.
		if ct.Risk == 0 || ct.Risk >= r.RiskTier.Risk || a.ImpactScore < 4 {
			continue
		}

		// share: how much of the request's value this child carries. Approximate:
		// it divides Change-VIS (matched occurrences) by CR-VIS (fully-addressed
		// advisories), two different scopes, so it can exceed 1.0; it is a ranking
		// heuristic, not an exact ratio.
		share := a.ImpactScore / r.ImpactScore
		// childVME: the child's own efficiency, value per unit of its merge risk.
		childVME := a.ImpactScore / float64(ct.Risk)

		// Qualifies when the child carries the bulk of the value, or is markedly
		// more efficient than merging the whole request.
		qualifies := share >= 0.7 || childVME >= 1.5*crVME
		if !qualifies {
			continue
		}

		candidate := &model.SplitCandidate{
			DependencyName:  a.Change.DependencyName,
			ImpactScore:     a.ImpactScore,
			ShareOfRequest:  share,
			RiskTier:        ct,
			MergeEfficiency: childVME,
		}

		if best == nil || share > best.ShareOfRequest ||
			(share == best.ShareOfRequest && a.Change.DependencyName < best.DependencyName) {
			best = candidate
		}
	}
	return best
}
