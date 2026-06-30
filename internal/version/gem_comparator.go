package version

import gem "github.com/aquasecurity/go-gem-version"

type gemComparator struct{}

func (gemComparator) Compare(a, b string) (int, error) {
	va, err := gem.NewVersion(a)
	if err != nil {
		return 0, &ParseError{Version: a, Reason: err.Error()}
	}
	vb, err := gem.NewVersion(b)
	if err != nil {
		return 0, &ParseError{Version: b, Reason: err.Error()}
	}
	if va.GreaterThan(vb) {
		return 1, nil
	}
	if va.LessThan(vb) {
		return -1, nil
	}
	return 0, nil
}
