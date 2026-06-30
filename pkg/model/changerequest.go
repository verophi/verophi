package model

import "time"

// ChangeRequestStatus represents the lifecycle state of a change request.
type ChangeRequestStatus string

const (
	StatusParsed    ChangeRequestStatus = "parsed"
	StatusMatched   ChangeRequestStatus = "matched"
	StatusUnmatched ChangeRequestStatus = "unmatched"
	StatusUnparsed  ChangeRequestStatus = "unparsed"
)

// SplitCandidate identifies a lower-risk child that carries a disproportionate
// share of the request's VIS, surfaced as a split hint.
type SplitCandidate struct {
	DependencyName  string     `json:"dependencyName"`
	ImpactScore     float64    `json:"impactScore"`
	ShareOfRequest  float64    `json:"shareOfRequest"`
	RiskTier        ChangeType `json:"riskTier"`
	MergeEfficiency float64    `json:"mergeEfficiency"`
}

// FixSummary is the per-request breakdown of the advisories the request fully
// addresses, by severity. The severity-weighted sum equals the request's
// ImpactScore (CR-VIS), so consumers and the human output do not recompute it.
type FixSummary struct {
	Total          int `json:"total"`
	SeverityCounts     // critical/high/medium/low, serialized flat
}

// ChangeRequest is the aggregate root: one source merge/pull request.
// It is a concrete struct with no interface fields so it can be decoded
// from JSON by verophi-inttest.
type ChangeRequest struct {
	Number          int                 `json:"number"`
	URL             string              `json:"url"`
	Title           string              `json:"title"`
	Platform        string              `json:"platform"`
	CreatedAt       time.Time           `json:"-"`
	AgeDays         int                 `json:"ageDays"`
	Labels          []string            `json:"labels"`
	Status          ChangeRequestStatus `json:"status"`
	RiskTier        ChangeType          `json:"riskTier"`
	HasUnknownRisk  bool                `json:"hasUnknownRisk"`
	SplitCandidate  *SplitCandidate     `json:"splitCandidate"`
	Stale           bool                `json:"stale"`
	ImpactScore     float64             `json:"impactScore"`
	MergeEfficiency *float64            `json:"mergeEfficiency"`
	Fixes           FixSummary          `json:"fixes"`
	Assessments     []ChangeAssessment  `json:"assessments"`
	UnparsedDeps    int                 `json:"unparsedDeps,omitempty"`
}

// ComputeRiskTier returns the highest-risk child ChangeType ignoring Risk 0.
// Ties resolve to the lexicographically smallest Name. If all children are
// Risk 0 (or there are no assessments), it returns ChangeUnknown.
func ComputeRiskTier(assessments []ChangeAssessment) ChangeType {
	best := ChangeUnknown
	found := false
	for _, a := range assessments {
		ct := a.Change.ChangeType
		if ct.Risk == 0 {
			continue
		}
		if !found || ct.Risk > best.Risk || (ct.Risk == best.Risk && ct.Name < best.Name) {
			best = ct
			found = true
		}
	}
	if !found {
		return ChangeUnknown
	}
	return best
}
