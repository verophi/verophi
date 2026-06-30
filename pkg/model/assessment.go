package model

// Confidence indicates the quality of an advisory match.
type Confidence string

const (
	ConfidenceHigh    Confidence = "high"
	ConfidenceLower   Confidence = "lower"
	ConfidenceUnknown Confidence = "unknown"
)

// AdvisoryMatch links an advisory (identity only) to a specific occurrence
// that a change fixes.
//
// Confidence is computed but intentionally not exposed in JSON output. The
// current heuristic (high when targetVersion >= patchedVersion) is too
// simplistic for user-facing display, and a match is only ever created for a
// confirmed fix, so it is always "high" today. A future iteration should
// incorporate source-of-match (description vs title vs branch), PURL-level
// verification, and groupId matching before it earns a place in the contract.
type AdvisoryMatch struct {
	Advisory   AdvisoryRef `json:"advisory"`
	Occurrence Occurrence  `json:"occurrence"`
	Confidence Confidence  `json:"-"`
}

// ChangeAssessment holds the per-dependency assessment within a change request.
// There is no standalone mergeEfficiency field; per-child efficiency exists
// only inside SplitCandidate.
type ChangeAssessment struct {
	Change          Change          `json:"change"`
	AdvisoryMatches []AdvisoryMatch `json:"advisoryMatches"`
	ImpactScore     float64         `json:"impactScore"`
}
