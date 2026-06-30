package model

// Advisory represents a vulnerability (CVE/GHSA) with its affected components.
// Aliases and CVSS are populated from the SBOM but intentionally not exposed in
// JSON: they do not feed scoring or matching (severity carries the weight) and
// are reserved for a Phase 2 richer presentation.
type Advisory struct {
	ID                   string       `json:"id"`
	Aliases              []string     `json:"-"`
	Severity             Severity     `json:"severity"`
	CVSS                 float64      `json:"-"`
	Recommendation       string       `json:"recommendation"`
	Occurrences          []Occurrence `json:"occurrences"`
	AddressedOccurrences int          `json:"addressedOccurrences"`
}

// AdvisoryRef is the identity-only projection of an Advisory, used inside
// AdvisoryMatch. It omits recommendation, occurrences, and addressedOccurrences
// so the round-trip (Marshal -> Unmarshal -> DeepEqual) does not break on zero
// values for those fields. Aliases and CVSS are kept on the struct but not
// serialized (see Advisory).
type AdvisoryRef struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"-"`
	Severity Severity `json:"severity"`
	CVSS     float64  `json:"-"`
}

// Occurrence represents a single affected component of an advisory.
type Occurrence struct {
	BOMRef          string `json:"bomRef"`
	PURL            string `json:"purl"`
	DependencyName  string `json:"dependencyName"`
	Ecosystem       string `json:"ecosystem"`
	AffectedVersion string `json:"affectedVersion"`
	FixVersion      string `json:"fixVersion"`
	Addressed       bool   `json:"addressed"`
}
