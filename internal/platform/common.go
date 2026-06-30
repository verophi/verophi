package platform

import (
	"time"
)

const DefaultMaxRequests = 1000

// ReadOptions bundles the parameters for a platform read.
type ReadOptions struct {
	PlatformTag string
	Token       string
	BaseURL     string
	Repository  string
	Filter      ChangeRequestFilter
	Limits      FetchLimits
}

type ChangeRequestFilter struct {
	Label        string
	BranchPrefix string
}

type FetchLimits struct {
	MaxRequests int
}

func (l FetchLimits) effectiveMaxRequests() int {
	if l.MaxRequests <= 0 {
		return DefaultMaxRequests
	}
	return l.MaxRequests
}

// ChangeRequestRaw carries the raw platform data for one change request before domain processing.
type ChangeRequestRaw struct {
	Number      int
	URL         string
	Title       string
	Platform    string
	Labels      []string
	CreatedAt   time.Time
	Description string
	Branch      string
}

// ReadResult is the outcome of a platform read operation.
type ReadResult struct {
	Requests  []ChangeRequestRaw
	Checked   int
	Truncated bool
}

type AuthenticationRequiredError struct {
	Message string
}

func (e *AuthenticationRequiredError) Error() string { return e.Message }

type RateLimitExceededError struct {
	Message string
}

func (e *RateLimitExceededError) Error() string { return e.Message }

func DefaultRenovateFilter() ChangeRequestFilter {
	return ChangeRequestFilter{
		Label:        "renovate",
		BranchPrefix: "renovate/",
	}
}

func normalizeFilter(filter ChangeRequestFilter) ChangeRequestFilter {
	defaults := DefaultRenovateFilter()
	if filter.Label == "" {
		filter.Label = defaults.Label
	}
	if filter.BranchPrefix == "" {
		filter.BranchPrefix = defaults.BranchPrefix
	}
	return filter
}
