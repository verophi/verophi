// Package semver provides semantic version comparison utilities.
package semver

import (
	"fmt"
	"strconv"
	"strings"
)

type Version struct {
	Major      int
	Minor      int
	Patch      int
	Extra      int // optional 4th segment (e.g. Ruby: 6.1.7.8)
	PreRelease string
	Raw        string
}

// Parse parses a version string into a Version struct.
// Accepts formats like "1.2.3", "v1.2.3", "1.2.3-rc1", "1.2".
func Parse(s string) (Version, error) {
	raw := s
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")

	var preRelease string
	if idx := strings.IndexByte(s, '-'); idx != -1 {
		preRelease = s[idx+1:]
		s = s[:idx]
	}
	if idx := strings.IndexByte(s, '+'); idx != -1 {
		s = s[:idx]
	}

	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 4 {
		return Version{}, fmt.Errorf("invalid version format: %q", raw)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return Version{}, fmt.Errorf("invalid major version in %q: %w", raw, err)
	}

	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return Version{}, fmt.Errorf("invalid minor version in %q: %w", raw, err)
	}

	patch := 0
	if len(parts) >= 3 {
		patch, err = strconv.Atoi(parts[2])
		if err != nil {
			return Version{}, fmt.Errorf("invalid patch version in %q: %w", raw, err)
		}
	}

	extra := 0
	if len(parts) == 4 {
		extra, err = strconv.Atoi(parts[3])
		if err != nil {
			return Version{}, fmt.Errorf("invalid extra version segment in %q: %w", raw, err)
		}
	}

	return Version{
		Major:      major,
		Minor:      minor,
		Patch:      patch,
		Extra:      extra,
		PreRelease: preRelease,
		Raw:        raw,
	}, nil
}
