package version

import "github.com/verophi/verophi/internal/version/maven"

type mavenComparator struct{}

func (mavenComparator) Compare(a, b string) (int, error) {
	va, err := maven.NewVersion(a)
	if err != nil {
		return 0, &ParseError{Version: a, Reason: err.Error()}
	}
	vb, err := maven.NewVersion(b)
	if err != nil {
		return 0, &ParseError{Version: b, Reason: err.Error()}
	}
	return va.Compare(vb), nil
}
