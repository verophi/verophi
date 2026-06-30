package semver

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	tests := []struct {
		input   string
		want    Version
		wantErr bool
	}{
		{"1.2.3", Version{Major: 1, Minor: 2, Patch: 3, Raw: "1.2.3"}, false},
		{"v1.2.3", Version{Major: 1, Minor: 2, Patch: 3, Raw: "v1.2.3"}, false},
		{"0.0.1", Version{Major: 0, Minor: 0, Patch: 1, Raw: "0.0.1"}, false},
		{"2.21.0", Version{Major: 2, Minor: 21, Patch: 0, Raw: "2.21.0"}, false},
		{"1.0.0-rc1", Version{Major: 1, Minor: 0, Patch: 0, PreRelease: "rc1", Raw: "1.0.0-rc1"}, false},
		{"1.2", Version{Major: 1, Minor: 2, Patch: 0, Raw: "1.2"}, false},
		{"v3.0.0-beta.1", Version{Major: 3, Minor: 0, Patch: 0, PreRelease: "beta.1", Raw: "v3.0.0-beta.1"}, false},
		{"1.0.0+build123", Version{Major: 1, Minor: 0, Patch: 0, Raw: "1.0.0+build123"}, false},
		{"6.1.7.8", Version{Major: 6, Minor: 1, Patch: 7, Extra: 8, Raw: "6.1.7.8"}, false},
		{"", Version{}, true},
		{"abc", Version{}, true},
		{"1", Version{}, true},
		{"1.2.3.4.5", Version{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := Parse(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want.Major, got.Major)
			assert.Equal(t, tt.want.Minor, got.Minor)
			assert.Equal(t, tt.want.Patch, got.Patch)
			assert.Equal(t, tt.want.PreRelease, got.PreRelease)
		})
	}
}

func TestParse_Errors(t *testing.T) {
	cases := []string{
		"1",         // too few segments
		"1.2.3.4.5", // too many segments
		"x.2.3",     // bad major
		"1.y.3",     // bad minor
		"1.2.z",     // bad patch
		"1.2.3.w",   // bad extra
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			_, err := Parse(c)
			assert.Error(t, err)
		})
	}
}

func TestParse_PrereleaseAndBuildAndVPrefix(t *testing.T) {
	v, err := Parse("v1.2.3-rc1")
	assert.NoError(t, err)
	assert.Equal(t, 1, v.Major)
	assert.Equal(t, 2, v.Minor)
	assert.Equal(t, 3, v.Patch)
	assert.Equal(t, "rc1", v.PreRelease)

	// build metadata after the patch is stripped
	b, err := Parse("1.2.3+build5")
	assert.NoError(t, err)
	assert.Equal(t, 3, b.Patch)
	assert.Equal(t, "", b.PreRelease)
}
