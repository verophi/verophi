package platform

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultRenovateFilter(t *testing.T) {
	f := DefaultRenovateFilter()
	assert.Equal(t, "renovate", f.Label)
	assert.Equal(t, "renovate/", f.BranchPrefix)
}

func TestEffectiveMaxRequests(t *testing.T) {
	assert.Equal(t, DefaultMaxRequests, FetchLimits{}.effectiveMaxRequests())
	assert.Equal(t, 50, FetchLimits{MaxRequests: 50}.effectiveMaxRequests())
	assert.Equal(t, DefaultMaxRequests, FetchLimits{MaxRequests: -1}.effectiveMaxRequests())
}

func TestSplitGithubRepoHelper(t *testing.T) {
	owner, name, err := splitGithubRepo("octocat/hello-world")
	assert.NoError(t, err)
	assert.Equal(t, "octocat", owner)
	assert.Equal(t, "hello-world", name)

	_, _, err = splitGithubRepo("invalid")
	assert.Error(t, err)
}
