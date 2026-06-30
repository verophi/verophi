package output

import (
	"sort"
	"strings"

	"github.com/verophi/verophi/pkg/model"
)

// partialFix records that a change request matches some but not all occurrences
// of an advisory, and there is NO partner request covering the rest. The
// advisory is uncorrelated (partially addressed). This is the complement of
// jointFix (which covers the "collectively reducible" case where partners exist).
type partialFix struct {
	advisoryID string
	severity   model.Severity
	blockers   []string // unaddressed dependency names, sorted
}

// computePartialFixes returns, per change-request number, the advisories it
// partially addresses: some occurrences matched, not all, and no partner request
// covers the rest (the complement of computeJointFixes).
func computePartialFixes(result *model.AnalysisResult) map[int][]partialFix {
	crMatchedOcc := map[int]map[string]map[string]bool{} // cr -> advID -> set(bomRef)
	for i := range result.ChangeRequests {
		cr := &result.ChangeRequests[i]
		for _, a := range cr.Assessments {
			for _, m := range a.AdvisoryMatches {
				if crMatchedOcc[cr.Number] == nil {
					crMatchedOcc[cr.Number] = map[string]map[string]bool{}
				}
				if crMatchedOcc[cr.Number][m.Advisory.ID] == nil {
					crMatchedOcc[cr.Number][m.Advisory.ID] = map[string]bool{}
				}
				crMatchedOcc[cr.Number][m.Advisory.ID][m.Occurrence.BOMRef] = true
			}
		}
	}

	out := map[int][]partialFix{}
	for _, adv := range result.UncorrelatedAdvisories {
		if adv.AddressedOccurrences == 0 || adv.AddressedOccurrences >= len(adv.Occurrences) {
			continue
		}
		var blockers []string
		for _, occ := range adv.Occurrences {
			if !occ.Addressed {
				blockers = append(blockers, occ.DependencyName)
			}
		}
		sort.Strings(blockers)

		for crNum, advMap := range crMatchedOcc {
			if len(advMap[adv.ID]) > 0 {
				out[crNum] = append(out[crNum], partialFix{
					advisoryID: adv.ID,
					severity:   adv.Severity,
					blockers:   blockers,
				})
			}
		}
	}

	for crNum := range out {
		ps := out[crNum]
		sort.SliceStable(ps, func(i, j int) bool {
			if ps[i].severity.Weight != ps[j].severity.Weight {
				return ps[i].severity.Weight > ps[j].severity.Weight
			}
			return ps[i].advisoryID < ps[j].advisoryID
		})
	}
	return out
}

// partialBlockerUnion returns the deduplicated, sorted blockers across a
// request's partial fixes (for the compact flag).
func partialBlockerUnion(partials []partialFix) string {
	set := map[string]bool{}
	for _, pf := range partials {
		for _, b := range pf.blockers {
			set[b] = true
		}
	}
	if len(set) == 0 {
		return ""
	}
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}
