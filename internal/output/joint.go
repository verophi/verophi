package output

import (
	"sort"

	"github.com/verophi/verophi/pkg/model"
)

// jointFix records that a change request only partially covers an advisory whose
// remaining occurrences are covered by other open requests (partners). Merging
// the partners together fully removes the advisory. It is a presentation-only
// relation derived from the analysis result; it is not part of the JSON contract.
type jointFix struct {
	advisoryID string
	severity   model.Severity
	partners   []int // partner change-request numbers, ascending
}

func occKey(o model.Occurrence) string { return o.BOMRef + "|" + o.PURL }

// computeJointFixes returns, per change-request number, the advisories it only
// partially addresses but that are collectively fully addressed by it plus other
// open requests. Advisories present in UncorrelatedAdvisories are not collectively
// fixable (some occurrence has no fix) and are skipped.
func computeJointFixes(result *model.AnalysisResult) map[int][]jointFix {
	fullOccs := map[string]map[string]bool{}     // advID -> set of occKeys (union of matched)
	severity := map[string]model.Severity{}      // advID -> severity
	crsByAdvOcc := map[string]map[string][]int{} // advID -> occKey -> []crNumber
	crAdvOccs := map[int]map[string]map[string]bool{}

	for i := range result.ChangeRequests {
		cr := &result.ChangeRequests[i]
		for _, a := range cr.Assessments {
			for _, m := range a.AdvisoryMatches {
				adv := m.Advisory.ID
				key := occKey(m.Occurrence)
				if fullOccs[adv] == nil {
					fullOccs[adv] = map[string]bool{}
				}
				fullOccs[adv][key] = true
				severity[adv] = m.Advisory.Severity
				if crsByAdvOcc[adv] == nil {
					crsByAdvOcc[adv] = map[string][]int{}
				}
				crsByAdvOcc[adv][key] = appendUniqueInt(crsByAdvOcc[adv][key], cr.Number)
				if crAdvOccs[cr.Number] == nil {
					crAdvOccs[cr.Number] = map[string]map[string]bool{}
				}
				if crAdvOccs[cr.Number][adv] == nil {
					crAdvOccs[cr.Number][adv] = map[string]bool{}
				}
				crAdvOccs[cr.Number][adv][key] = true
			}
		}
	}

	uncorrelated := map[string]bool{}
	for _, adv := range result.UncorrelatedAdvisories {
		uncorrelated[adv.ID] = true
	}

	out := map[int][]jointFix{}
	for crNum, advs := range crAdvOccs {
		for adv, mine := range advs {
			if uncorrelated[adv] {
				continue // not collectively fixable (Fall 2)
			}
			full := fullOccs[adv]
			if len(mine) == len(full) {
				continue // this request alone fully addresses the advisory
			}
			partnerSet := map[int]bool{}
			for key := range full {
				if mine[key] {
					continue
				}
				for _, cn := range crsByAdvOcc[adv][key] {
					if cn != crNum {
						partnerSet[cn] = true
					}
				}
			}
			if len(partnerSet) == 0 {
				continue
			}
			out[crNum] = append(out[crNum], jointFix{
				advisoryID: adv,
				severity:   severity[adv],
				partners:   sortedInts(partnerSet),
			})
		}
	}

	for crNum := range out {
		js := out[crNum]
		sort.SliceStable(js, func(i, j int) bool {
			if js[i].severity.Weight != js[j].severity.Weight {
				return js[i].severity.Weight > js[j].severity.Weight
			}
			return js[i].advisoryID < js[j].advisoryID
		})
	}
	return out
}

// jointPartnerUnion returns the deduplicated, ascending set of all partner
// numbers across a request's joint fixes (for the compact flag).
func jointPartnerUnion(joints []jointFix) []int {
	set := map[int]bool{}
	for _, jf := range joints {
		for _, p := range jf.partners {
			set[p] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	return sortedInts(set)
}

func appendUniqueInt(s []int, v int) []int {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func sortedInts(set map[int]bool) []int {
	out := make([]int, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}
