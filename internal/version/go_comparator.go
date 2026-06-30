package version

import "golang.org/x/mod/semver"

// goComparator implements Comparator for Go module versions using the official
// x/mod/semver package. It canonicalizes inputs to v-prefixed versions before
// comparison, since SBOM affected versions are v-prefixed while recommendations
// are not.
type goComparator struct{}

func (goComparator) Compare(a, b string) (int, error) {
	a = canonicalizeGo(a)
	b = canonicalizeGo(b)
	if !semver.IsValid(a) {
		return 0, &ParseError{Version: a, Reason: "invalid Go module version"}
	}
	if !semver.IsValid(b) {
		return 0, &ParseError{Version: b, Reason: "invalid Go module version"}
	}
	return semver.Compare(a, b), nil
}

func canonicalizeGo(v string) string {
	if len(v) > 0 && v[0] != 'v' {
		return "v" + v
	}
	return v
}
