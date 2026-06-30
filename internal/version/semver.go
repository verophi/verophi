package version

import "strconv"

// ParseError is returned when a version string cannot be parsed.
type ParseError struct {
	Version string
	Reason  string
}

func (e *ParseError) Error() string {
	return "cannot parse version " + strconv.Quote(e.Version) + ": " + e.Reason
}
