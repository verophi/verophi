package version_info

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultValues(t *testing.T) {
	assert.Equal(t, "dev", Version)
	assert.Equal(t, "unknown", Commit)
	assert.Equal(t, "unknown", BuildDate)
}

// TestMakefileLDFlagsTargetThisPackage guards the release version injection: the
// -X ldflags must reference this package's symbols. They previously pointed at
// internal/version (the comparator package, which has no Version/Commit/
// BuildDate vars), so the linker silently dropped the injection and every
// release shipped as "dev"/"unknown".
func TestMakefileLDFlagsTargetThisPackage(t *testing.T) {
	data, err := os.ReadFile("../../Makefile")
	require.NoError(t, err)
	mk := string(data)

	for _, sym := range []string{"Version", "Commit", "BuildDate"} {
		assert.Contains(t, mk, "internal/version_info."+sym+"=",
			"Makefile must inject %s via -X internal/version_info.%s", sym, sym)
		assert.NotContains(t, mk, "internal/version."+sym+"=",
			"Makefile must not target internal/version.%s (no such symbol, injection is dropped)", sym)
	}
}
