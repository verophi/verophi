package version

// Result of a version comparison against a fix version.
type Result string

const (
	Fixed    Result = "fixed"
	Affected Result = "affected"
	Unknown  Result = "unknown"
)

// Comparator compares versions within a single ecosystem.
type Comparator interface {
	// Compare returns -1 if a < b, 0 if a == b, +1 if a > b.
	// Returns an error if either version is unparseable.
	Compare(a, b string) (int, error)
}

// Tier describes the support level for an ecosystem.
type Tier string

const (
	Supported  Tier = "supported"
	BestEffort Tier = "best-effort"
	Limited    Tier = "limited"
)

// EcosystemInfo describes a supported ecosystem.
type EcosystemInfo struct {
	Ecosystem string
	Tier      Tier
}

// SupportMatrix lists all ecosystems with their support tier.
var SupportMatrix = []EcosystemInfo{
	{"go", Supported},
	{"npm", Supported},
	{"pypi", Supported},
	{"gem", Supported},
	{"maven", Supported},
	{"cargo", BestEffort},
	{"hex", BestEffort},
	{"pub", BestEffort},
	{"swift", BestEffort},
	{"nuget", BestEffort},
	{"composer", BestEffort},
}

// For returns the Comparator for the given ecosystem, or nil if unsupported.
func For(ecosystem string) Comparator {
	switch ecosystem {
	case "go", "golang":
		return goComparator{}
	case "npm":
		return genericComparator{}
	case "pypi", "pip":
		return pep440Comparator{}
	case "gem", "bundler":
		return gemComparator{}
	case "maven", "pom":
		return mavenComparator{}
	case "cargo", "hex", "pub", "swift", "nuget", "composer":
		return genericComparator{}
	default:
		return nil
	}
}

// IsFixedBy checks whether targetVersion >= fixVersion for the given ecosystem.
// Returns fixed, affected, or unknown.
func IsFixedBy(ecosystem, targetVersion, fixVersion string) Result {
	c := For(ecosystem)
	if c == nil {
		return Unknown
	}
	cmp, err := c.Compare(targetVersion, fixVersion)
	if err != nil {
		return Unknown
	}
	if cmp >= 0 {
		return Fixed
	}
	return Affected
}
