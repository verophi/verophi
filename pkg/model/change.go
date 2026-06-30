package model

// ChangeType is a value object {Name, Risk}, symmetric to Severity.
type ChangeType struct {
	Name string `json:"name"`
	Risk int    `json:"risk"`
}

var (
	ChangePatch       = ChangeType{Name: "patch", Risk: 1}
	ChangeMinor       = ChangeType{Name: "minor", Risk: 2}
	ChangeMajor       = ChangeType{Name: "major", Risk: 3}
	ChangePin         = ChangeType{Name: "pin", Risk: 1}
	ChangePinDigest   = ChangeType{Name: "pinDigest", Risk: 1}
	ChangeBump        = ChangeType{Name: "bump", Risk: 1}
	ChangeRollback    = ChangeType{Name: "rollback", Risk: 3}
	ChangeDigest      = ChangeType{Name: "digest", Risk: 0}
	ChangeReplacement = ChangeType{Name: "replacement", Risk: 0}
	ChangeMaintenance = ChangeType{Name: "lockFileMaintenance", Risk: 0}
	ChangeUnknown     = ChangeType{Name: "unknown", Risk: 0}
)

// Change represents a single dependency update within a change request.
type Change struct {
	DependencyName string     `json:"dependencyName"`
	CurrentVersion string     `json:"currentVersion"`
	TargetVersion  string     `json:"targetVersion"`
	ChangeType     ChangeType `json:"changeType"`
}
