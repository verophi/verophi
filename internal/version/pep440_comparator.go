package version

import pep440 "github.com/aquasecurity/go-pep440-version"

type pep440Comparator struct{}

func (pep440Comparator) Compare(a, b string) (int, error) {
	va, err := pep440.Parse(a)
	if err != nil {
		return 0, &ParseError{Version: a, Reason: err.Error()}
	}
	vb, err := pep440.Parse(b)
	if err != nil {
		return 0, &ParseError{Version: b, Reason: err.Error()}
	}
	return va.Compare(vb), nil
}
