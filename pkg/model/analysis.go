package model

const SchemaVersion = "1.0"

const (
	CorrelationNotRun   = "not_run"
	CorrelationComplete = "complete"
	CorrelationFailed   = "failed"
)

type Correlation struct {
	Status     string `json:"status"`
	Platform   string `json:"platform"`
	Repository string `json:"repository"`
}

// SeverityCounts is a per-severity tally, reused wherever a C/H/M/L breakdown is
// needed. Embedded anonymously so its fields serialize flat (critical/high/...).
type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// Add increments the bucket for the given severity. Unknown-severity advisories
// (Weight 0) fall through and are not bucketed.
func (c *SeverityCounts) Add(s Severity) {
	switch s.Level {
	case "Critical":
		c.Critical++
	case "High":
		c.High++
	case "Medium":
		c.Medium++
	case "Low":
		c.Low++
	}
}

type AdvisorySummary struct {
	Total          int `json:"total"`
	Correlated     int `json:"correlated"`
	Uncorrelated   int `json:"uncorrelated"`
	SeverityCounts     // critical/high/medium/low, serialized flat
}

// AnalysisResult is the top-level output of the analysis, and the decode target
// for verophi-inttest. All slice fields serialize as [] (never null) via
// Normalize; pointer fields serialize as null when nil.
type AnalysisResult struct {
	SchemaVersion          string          `json:"schemaVersion"`
	Correlation            Correlation     `json:"correlation"`
	AdvisorySummary        AdvisorySummary `json:"advisorySummary"`
	TotalImpactScore       float64         `json:"totalImpactScore"`
	ReducibleImpactScore   *float64        `json:"reducibleImpactScore"`
	ChangeRequests         []ChangeRequest `json:"changeRequests"`
	UncorrelatedAdvisories []Advisory      `json:"uncorrelatedAdvisories"`
}

// Normalize ensures all slice fields are non-nil (empty rather than null in
// JSON). Call before marshaling so the round-trip (Unmarshal -> DeepEqual)
// succeeds.
func (r *AnalysisResult) Normalize() {
	if r.ChangeRequests == nil {
		r.ChangeRequests = []ChangeRequest{}
	}
	if r.UncorrelatedAdvisories == nil {
		r.UncorrelatedAdvisories = []Advisory{}
	}
	for i := range r.ChangeRequests {
		normalizeChangeRequest(&r.ChangeRequests[i])
	}
	for i := range r.UncorrelatedAdvisories {
		normalizeAdvisory(&r.UncorrelatedAdvisories[i])
	}
}

func normalizeChangeRequest(r *ChangeRequest) {
	if r.Labels == nil {
		r.Labels = []string{}
	}
	if r.Assessments == nil {
		r.Assessments = []ChangeAssessment{}
	}
	for i := range r.Assessments {
		normalizeAssessment(&r.Assessments[i])
	}
}

func normalizeAssessment(a *ChangeAssessment) {
	if a.AdvisoryMatches == nil {
		a.AdvisoryMatches = []AdvisoryMatch{}
	}
	for i := range a.AdvisoryMatches {
		normalizeAdvisoryMatch(&a.AdvisoryMatches[i])
	}
}

func normalizeAdvisoryMatch(m *AdvisoryMatch) {
	if m.Advisory.Aliases == nil {
		m.Advisory.Aliases = []string{}
	}
}

func normalizeAdvisory(adv *Advisory) {
	if adv.Aliases == nil {
		adv.Aliases = []string{}
	}
	if adv.Occurrences == nil {
		adv.Occurrences = []Occurrence{}
	}
}
