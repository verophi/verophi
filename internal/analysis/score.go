package analysis

import "github.com/verophi/verophi/pkg/model"

// scoreAssessments computes Change-VIS for each assessment.
func scoreAssessments(requests []model.ChangeRequest) {
	for ri := range requests {
		r := &requests[ri]
		for ai := range r.Assessments {
			a := &r.Assessments[ai]
			var vis float64
			for _, m := range a.AdvisoryMatches {
				vis += float64(m.Advisory.Severity.Weight)
			}
			a.ImpactScore = vis
		}
	}
}

// scoreCRVIS computes CR-VIS: sum of severity weights of advisories the request
// fully addresses (every occurrence globally), each counted once.
func scoreCRVIS(advisories []model.Advisory, requests []model.ChangeRequest) {
	for ri := range requests {
		r := &requests[ri]
		if r.Status != model.StatusMatched {
			continue
		}

		matchedAdvIDs := make(map[string]bool)
		for _, a := range r.Assessments {
			for _, m := range a.AdvisoryMatches {
				matchedAdvIDs[m.Advisory.ID] = true
			}
		}

		var crVIS float64
		fixes := model.FixSummary{}
		for _, adv := range advisories {
			if !matchedAdvIDs[adv.ID] {
				continue
			}
			if requestFullyAddresses(r, &adv) {
				crVIS += float64(adv.Severity.Weight)
				fixes.Total++
				fixes.Add(adv.Severity)
			}
		}
		r.ImpactScore = crVIS
		r.Fixes = fixes
	}
}

// requestFullyAddresses checks if a single request fixes ALL occurrences of an advisory.
func requestFullyAddresses(cr *model.ChangeRequest, adv *model.Advisory) bool {
	if len(adv.Occurrences) == 0 {
		return false
	}
	for _, occ := range adv.Occurrences {
		if !occurrenceMatchedBy(cr, adv.ID, occ) {
			return false
		}
	}
	return true
}

// occurrenceMatchedBy reports whether the request carries an AdvisoryMatch for
// THIS advisory on the given occurrence. It keys on the advisory id as well as
// the component (BOMRef+PURL): many advisories share one component occurrence
// with different fix versions, so a match for one advisory must not count as a
// match for another on the same component (R7.1, R12.4).
func occurrenceMatchedBy(cr *model.ChangeRequest, advID string, occ model.Occurrence) bool {
	for _, a := range cr.Assessments {
		for _, m := range a.AdvisoryMatches {
			if m.Advisory.ID == advID && m.Occurrence.BOMRef == occ.BOMRef && m.Occurrence.PURL == occ.PURL {
				return true
			}
		}
	}
	return false
}

// computeReducible computes ReducibleImpactScore: advisories collectively fully
// addressed across all requests, deduplicated globally.
func computeReducible(advisories []model.Advisory, requests []model.ChangeRequest) float64 {
	var reducible float64
	for _, adv := range advisories {
		if collectivelyAddressed(&adv, requests) {
			reducible += float64(adv.Severity.Weight)
		}
	}
	return reducible
}

func collectivelyAddressed(adv *model.Advisory, requests []model.ChangeRequest) bool {
	if len(adv.Occurrences) == 0 {
		return false
	}
	for _, occ := range adv.Occurrences {
		if !anyRequestMatches(adv.ID, occ, requests) {
			return false
		}
	}
	return true
}

func anyRequestMatches(advID string, occ model.Occurrence, requests []model.ChangeRequest) bool {
	for ri := range requests {
		if occurrenceMatchedBy(&requests[ri], advID, occ) {
			return true
		}
	}
	return false
}

func computeAddressedOccurrences(advisories []model.Advisory, requests []model.ChangeRequest) {
	for ai := range advisories {
		adv := &advisories[ai]
		count := 0
		for oi := range adv.Occurrences {
			if anyRequestMatches(adv.ID, adv.Occurrences[oi], requests) {
				adv.Occurrences[oi].Addressed = true
				count++
			}
		}
		adv.AddressedOccurrences = count
	}
}

// computeTotalImpactScore sums severity weights of all advisories.
func computeTotalImpactScore(advisories []model.Advisory) float64 {
	var total float64
	for _, adv := range advisories {
		total += float64(adv.Severity.Weight)
	}
	return total
}
