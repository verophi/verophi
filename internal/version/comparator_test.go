package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFor_SupportedEcosystems(t *testing.T) {
	supported := []string{"go", "golang", "npm", "pypi", "pip", "gem", "bundler", "maven", "pom", "cargo", "hex", "pub", "swift", "nuget", "composer"}
	for _, eco := range supported {
		c := For(eco)
		assert.NotNil(t, c, "ecosystem %q should have a comparator", eco)
	}
}

func TestFor_UnsupportedEcosystems(t *testing.T) {
	unsupported := []string{"docker", "unknown", ""}
	for _, eco := range unsupported {
		c := For(eco)
		assert.Nil(t, c, "ecosystem %q should return nil", eco)
	}
}

func TestSemverComparator(t *testing.T) {
	tests := []struct {
		a, b     string
		expected int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.1", "1.0.0", 1},
		{"1.0.0", "1.0.1", -1},
		{"2.0.0", "1.99.99", 1},
		{"4.17.21", "4.17.20", 1},
		{"6.1.5.1", "6.1.5", 1},
		{"6.1.4", "6.1.5.1", -1},
		{"0.31.1", "0.21.1", 1},
		{"1.15.1", "0.31.1", 1},
		{"2.15.0", "2.14.1", 1},
		{"2.3.1", "2.14.1", -1},
		{"6.7.3", "6.7.0", 1},
		{"1.18.4", "1.17.0", 1},
	}
	c := genericComparator{}
	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			got, err := c.Compare(tt.a, tt.b)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestGoComparator_VPrefixCanonicalization(t *testing.T) {
	c := goComparator{}

	// v-prefixed SBOM vs bare recommendation
	cmp, err := c.Compare("v1.7.0", "1.7.7")
	require.NoError(t, err)
	assert.Equal(t, -1, cmp) // v1.7.0 < 1.7.7

	// both v-prefixed
	cmp, err = c.Compare("v1.7.7", "v1.7.0")
	require.NoError(t, err)
	assert.Equal(t, 1, cmp)

	// both bare
	cmp, err = c.Compare("0.17.0", "0.16.0")
	require.NoError(t, err)
	assert.Equal(t, 1, cmp)
}

func TestIsFixedBy(t *testing.T) {
	tests := []struct {
		eco, target, fix string
		expected         Result
	}{
		{"npm", "4.17.21", "4.17.21", Fixed},
		{"npm", "4.17.22", "4.17.21", Fixed},
		{"npm", "4.17.20", "4.17.21", Affected},
		{"nuget", "1.0.0", "1.0.1", Affected},
		{"go", "v1.7.7", "1.7.7", Fixed},
		{"go", "v1.7.0", "1.7.7", Affected},
	}
	for _, tt := range tests {
		t.Run(tt.eco+"/"+tt.target+"_vs_"+tt.fix, func(t *testing.T) {
			got := IsFixedBy(tt.eco, tt.target, tt.fix)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestSemverComparator_ParseError(t *testing.T) {
	c := genericComparator{}
	_, err := c.Compare("abc", "1.0.0")
	assert.Error(t, err)
	var pe *ParseError
	assert.ErrorAs(t, err, &pe)
}

// TestSupportMatrixMatchesFor guards that the documented SupportMatrix is the
// single source of truth for ecosystem support: every ecosystem in the matrix
// must resolve to a comparator via For(). This keeps the matrix from drifting
// away from For().
func TestSupportMatrixMatchesFor(t *testing.T) {
	for _, e := range SupportMatrix {
		t.Run(e.Ecosystem, func(t *testing.T) {
			assert.NotNil(t, For(e.Ecosystem), "%s is %s but has no comparator", e.Ecosystem, e.Tier)
		})
	}
}

// TestForUnknownEcosystemIsNil guards that an ecosystem absent from the matrix
// (e.g. docker tags) has no comparator.
func TestForUnknownEcosystemIsNil(t *testing.T) {
	assert.Nil(t, For("docker"))
	assert.Nil(t, For(""))
}

// TestParseError_Error covers the error string formatting.
func TestParseError_Error(t *testing.T) {
	e := &ParseError{Version: "abc", Reason: "non-numeric segment: abc"}
	msg := e.Error()
	assert.Contains(t, msg, "abc")
	assert.Contains(t, msg, "non-numeric segment")
}

// TestSemverComparator_BParseError covers the error path when the second operand
// is unparseable (the first operand parses fine).
func TestSemverComparator_BParseError(t *testing.T) {
	c := genericComparator{}
	_, err := c.Compare("1.0.0", "not-a-version")
	assert.Error(t, err)
}

// TestIsFixedBy_CompareError covers the path where the ecosystem is supported
// but a version is unparseable, so the comparison errors and the result is
// unknown (distinct from an unsupported ecosystem).
func TestIsFixedBy_CompareError(t *testing.T) {
	assert.Equal(t, Unknown, IsFixedBy("npm", "not-a-version", "1.0.0"))
}
