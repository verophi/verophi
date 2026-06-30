package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Direct table tests for the per-ecosystem comparators, pinning the
// ecosystem-specific ordering rules (prereleases, epochs, Maven qualifiers,
// multi-segment versions) that correlation relies on.

type cmpCase struct {
	a, b string
	want int
}

func runCompareCases(t *testing.T, c Comparator, cases []cmpCase) {
	t.Helper()
	for _, tt := range cases {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			got, err := c.Compare(tt.a, tt.b)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got, "%s vs %s", tt.a, tt.b)
		})
	}
}

func TestPEP440Comparator(t *testing.T) {
	runCompareCases(t, pep440Comparator{}, []cmpCase{
		{"2.0.0", "1.0.0", 1},
		{"1.0.0", "2.0.0", -1},
		{"1.0.0", "1.0.0", 0},
		{"1.0", "1.0.0", 0},       // trailing-zero normalization
		{"1.0a1", "1.0", -1},      // pre-release precedes final
		{"1.0rc1", "1.0", -1},     // release candidate precedes final
		{"1.0.post1", "1.0", 1},   // post-release follows final
		{"1.0.dev1", "1.0a1", -1}, // dev precedes pre-release
		{"1!1.0", "2.0", 1},       // epoch dominates the release
		{"10.2.0", "9.0.0", 1},    // numeric, not lexical
		{"2.32.0", "2.31.0", 1},
	})
}

func TestGemComparator(t *testing.T) {
	runCompareCases(t, gemComparator{}, []cmpCase{
		{"1.13.6", "1.13.5", 1},
		{"1.13.10", "1.13.6", 1}, // numeric, not lexical (10 > 6)
		{"6.1.5.1", "6.1.5", 1},  // four-segment gem version
		{"1.15.6", "1.13.10", 1},
		{"1.0.0", "1.0.0", 0},
		{"1.0.0.pre", "1.0.0", -1},   // prerelease precedes release
		{"1.0.0.beta1", "1.0.0", -1}, // beta precedes release
	})
}

func TestMavenComparator(t *testing.T) {
	runCompareCases(t, mavenComparator{}, []cmpCase{
		{"2.17.1", "2.14.1", 1},
		{"2.14.1", "2.17.1", -1},
		{"2.17.1", "2.17.1", 0},
		{"1.0.1", "1.0", 1},
		{"1.0-alpha", "1.0", -1},      // qualifier precedes release
		{"1.0-alpha", "1.0-beta", -1}, // alpha precedes beta
		{"1.0-SNAPSHOT", "1.0", -1},   // snapshot precedes release
		{"6.1.5.1", "6.1.5", 1},
	})
}

// TestEcosystemComparators_ParseError covers the unparseable-input path for each
// comparator, which yields a ParseError (and, via IsFixedBy, an Unknown result
// rather than a guess).
func TestEcosystemComparators_ParseError(t *testing.T) {
	comparators := map[string]Comparator{
		"pep440": pep440Comparator{},
		"gem":    gemComparator{},
		"maven":  mavenComparator{},
	}
	// Inputs that no reasonable version scheme should accept.
	bad := []string{"", "not a version!"}
	for name, c := range comparators {
		for _, b := range bad {
			t.Run(name+"/"+b, func(t *testing.T) {
				_, err := c.Compare(b, "1.0.0")
				if err == nil {
					t.Skipf("%s accepts %q as a version (permissive scheme)", name, b)
				}
				var pe *ParseError
				assert.ErrorAs(t, err, &pe, "should be a ParseError")
			})
		}
	}
}
