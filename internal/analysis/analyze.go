package analysis

import (
	"time"

	"github.com/verophi/verophi/pkg/model"
)

// Options bundles the parameters that tune an analysis run.
type Options struct {
	Now       time.Time
	StaleDays int
}

// Analyze correlates SBOM advisories with change requests, scores, flags,
// deduplicates, and orders the result. The injected clock (opts.Now) makes age
// and time-derived values deterministic.
func Analyze(sbom *model.SBOMResult, requests []model.ChangeRequest, corr model.Correlation, opts Options) *model.AnalysisResult {
	advisories := sbom.Advisories

	// 1. Compute AgeDays from each request's CreatedAt and the injected clock,
	// so age is deterministic
	computeAgeDays(requests, opts.Now)

	// 2. Correlate: match occurrences to changes
	correlate(advisories, requests)

	// 3. Score assessments (Change-VIS)
	scoreAssessments(requests)

	// 4. Score CR-VIS
	scoreCRVIS(advisories, requests)

	// 5. Compute flags (RiskTier, HasUnknownRisk, MergeEfficiency, SplitCandidate, Stale)
	computeFlags(requests, opts.StaleDays)

	// 6. Compute addressed occurrences for partially addressed advisories
	computeAddressedOccurrences(advisories, requests)

	// 7. Build summary and uncorrelated advisories
	totalImpact := computeTotalImpactScore(advisories)
	summary, uncorrelated := buildSummary(advisories)
	// 8. Compute reducible (only when correlation ran successfully)
	var reducible *float64
	if corr.Status == model.CorrelationComplete {
		reducible = new(computeReducible(advisories, requests))
	}

	result := &model.AnalysisResult{
		SchemaVersion:          model.SchemaVersion,
		Correlation:            corr,
		AdvisorySummary:        summary,
		TotalImpactScore:       totalImpact,
		ReducibleImpactScore:   reducible,
		ChangeRequests:         requests,
		UncorrelatedAdvisories: uncorrelated,
	}

	// 9. Order everything deterministically
	orderResult(result)

	// 10. Normalize nil slices
	result.Normalize()

	return result
}

func computeAgeDays(requests []model.ChangeRequest, now time.Time) {
	for i := range requests {
		if !requests[i].CreatedAt.IsZero() {
			requests[i].AgeDays = int(now.Sub(requests[i].CreatedAt).Hours() / 24)
		}
	}
}

func buildSummary(advisories []model.Advisory) (model.AdvisorySummary, []model.Advisory) {
	summary := model.AdvisorySummary{Total: len(advisories)}
	var uncorrelated []model.Advisory

	for _, adv := range advisories {
		summary.Add(adv.Severity)

		// AddressedOccurrences was populated by computeAddressedOccurrences;
		// an advisory is correlated if every occurrence is addressed.
		if len(adv.Occurrences) > 0 && adv.AddressedOccurrences == len(adv.Occurrences) {
			summary.Correlated++
		} else {
			summary.Uncorrelated++
			uncorrelated = append(uncorrelated, adv)
		}
	}

	return summary, uncorrelated
}
