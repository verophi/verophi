package model

// SBOMResult holds the parsed SBOM data: advisories with their occurrences
// and metadata about the SBOM format.
type SBOMResult struct {
	Advisories  []Advisory `json:"advisories"`
	Format      string     `json:"format"`
	SpecVersion string     `json:"specVersion"`
}
