package version

// genericComparator wraps aquasecurity/go-version for ecosystems that follow
// semver-like versioning with 3+ segments (cargo, hex, pub, swift, and the
// best-effort nuget/composer bucket).

import goversion "github.com/aquasecurity/go-version/pkg/version"

type genericComparator struct{}

func (genericComparator) Compare(a, b string) (int, error) {
	va, err := goversion.Parse(a)
	if err != nil {
		return 0, &ParseError{Version: a, Reason: err.Error()}
	}
	vb, err := goversion.Parse(b)
	if err != nil {
		return 0, &ParseError{Version: b, Reason: err.Error()}
	}
	return va.Compare(vb), nil
}
