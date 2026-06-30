package platform

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	gh "github.com/google/go-github/v85/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockPRService struct {
	handler func(ctx context.Context, owner, repo string, opts *gh.PullRequestListOptions) ([]*gh.PullRequest, *gh.Response, error)
}

func (m *mockPRService) List(ctx context.Context, owner, repo string, opts *gh.PullRequestListOptions) ([]*gh.PullRequest, *gh.Response, error) {
	return m.handler(ctx, owner, repo, opts)
}

func ptr[T any](v T) *T { return &v }

func TestFetchPRs_BasicFlow(t *testing.T) {
	createdAt := time.Now().Add(-48 * time.Hour)
	mock := &mockPRService{
		handler: func(_ context.Context, _, _ string, _ *gh.PullRequestListOptions) ([]*gh.PullRequest, *gh.Response, error) {
			return []*gh.PullRequest{
				{
					Number:  ptr(1),
					Title:   ptr("fix(deps): update dependency lodash to v4.18.1"),
					Body:    ptr("| [lodash](https://lodash.com) | [`4.17.20` → `4.18.1`](https://example.com) |"),
					HTMLURL: ptr("https://github.com/test/repo/pull/1"),
					Labels: []*gh.Label{
						{Name: ptr("renovate")},
						{Name: ptr("minor")},
					},
					Head:      &gh.PullRequestBranch{Ref: ptr("renovate/lodash-4.18.1")},
					CreatedAt: &gh.Timestamp{Time: createdAt},
				},
			}, &gh.Response{}, nil
		},
	}

	result, err := FetchPRs(context.Background(), mock, "test", "repo", DefaultRenovateFilter(), FetchLimits{}, "github")
	require.NoError(t, err)
	require.Len(t, result.Requests, 1)

	input := result.Requests[0]
	assert.Equal(t, "| [lodash](https://lodash.com) | [`4.17.20` → `4.18.1`](https://example.com) |", input.Description)
	assert.Equal(t, "fix(deps): update dependency lodash to v4.18.1", input.Title)
	assert.Equal(t, "renovate/lodash-4.18.1", input.Branch)
	assert.Equal(t, 1, input.Number)
	assert.Equal(t, "https://github.com/test/repo/pull/1", input.URL)
	assert.Equal(t, "github", input.Platform)
	assert.Equal(t, createdAt, input.CreatedAt)
	assert.Equal(t, []string{"renovate", "minor"}, input.Labels)
}

func TestFetchPRs_FiltersNonRenovate(t *testing.T) {
	mock := &mockPRService{
		handler: func(_ context.Context, _, _ string, _ *gh.PullRequestListOptions) ([]*gh.PullRequest, *gh.Response, error) {
			return []*gh.PullRequest{
				{
					Number: ptr(1),
					Title:  ptr("feat: add new feature"),
					Labels: []*gh.Label{{Name: ptr("feature")}},
					Head:   &gh.PullRequestBranch{Ref: ptr("feature/new-thing")},
				},
				{
					Number: ptr(2),
					Title:  ptr("fix(deps): update dependency axios to v1.0.0"),
					Body:   ptr("| [axios](https://axios-http.com) | [`0.21.1` → `1.0.0`](https://example.com) |"),
					Labels: []*gh.Label{{Name: ptr("renovate")}},
					Head:   &gh.PullRequestBranch{Ref: ptr("renovate/axios-1.x")},
				},
			}, &gh.Response{}, nil
		},
	}

	result, err := FetchPRs(context.Background(), mock, "test", "repo", DefaultRenovateFilter(), FetchLimits{}, "github")
	require.NoError(t, err)
	require.Len(t, result.Requests, 1)
	assert.Equal(t, "fix(deps): update dependency axios to v1.0.0", result.Requests[0].Title)
}

func TestFetchPRs_CustomLabel(t *testing.T) {
	mock := &mockPRService{
		handler: func(_ context.Context, _, _ string, _ *gh.PullRequestListOptions) ([]*gh.PullRequest, *gh.Response, error) {
			return []*gh.PullRequest{
				{
					Number: ptr(3),
					Title:  ptr("Update dependency express to v4.18.0"),
					Labels: []*gh.Label{{Name: ptr("dependencies")}},
					Head:   &gh.PullRequestBranch{Ref: ptr("dependabot/npm_and_yarn/express-4.18.0")},
				},
			}, &gh.Response{}, nil
		},
	}

	result, err := FetchPRs(context.Background(), mock, "test", "repo", ChangeRequestFilter{
		Label:        "dependencies",
		BranchPrefix: "renovate/",
	}, FetchLimits{}, "github")
	require.NoError(t, err)
	require.Len(t, result.Requests, 1)
	assert.Equal(t, 1, result.Checked)
	assert.Equal(t, "Update dependency express to v4.18.0", result.Requests[0].Title)
}

func TestFetchPRs_BranchPrefixOnly(t *testing.T) {
	mock := &mockPRService{
		handler: func(_ context.Context, _, _ string, _ *gh.PullRequestListOptions) ([]*gh.PullRequest, *gh.Response, error) {
			return []*gh.PullRequest{
				{
					Number: ptr(4),
					Title:  ptr("Update dependency chalk to v5.0.0"),
					Head:   &gh.PullRequestBranch{Ref: ptr("renovate/chalk-5.0.0")},
				},
			}, &gh.Response{}, nil
		},
	}

	result, err := FetchPRs(context.Background(), mock, "test", "repo", DefaultRenovateFilter(), FetchLimits{}, "github")
	require.NoError(t, err)
	require.Len(t, result.Requests, 1)
	assert.Equal(t, "Update dependency chalk to v5.0.0", result.Requests[0].Title)
	assert.Equal(t, "renovate/chalk-5.0.0", result.Requests[0].Branch)
}

func TestFetchPRs_CustomBranchPrefix(t *testing.T) {
	mock := &mockPRService{
		handler: func(_ context.Context, _, _ string, _ *gh.PullRequestListOptions) ([]*gh.PullRequest, *gh.Response, error) {
			return []*gh.PullRequest{
				{
					Number: ptr(7),
					Title:  ptr("Update dependency chalk to v5.0.0"),
					Head:   &gh.PullRequestBranch{Ref: ptr("bot/chalk-5.0.0")},
				},
			}, &gh.Response{}, nil
		},
	}

	result, err := FetchPRs(context.Background(), mock, "test", "repo", ChangeRequestFilter{
		Label:        "renovate",
		BranchPrefix: "bot/",
	}, FetchLimits{}, "github")
	require.NoError(t, err)
	require.Len(t, result.Requests, 1)
	assert.Equal(t, "bot/chalk-5.0.0", result.Requests[0].Branch)
}

func TestFetchPRs_EmptyResponse(t *testing.T) {
	mock := &mockPRService{
		handler: func(_ context.Context, _, _ string, _ *gh.PullRequestListOptions) ([]*gh.PullRequest, *gh.Response, error) {
			return []*gh.PullRequest{}, &gh.Response{}, nil
		},
	}

	result, err := FetchPRs(context.Background(), mock, "test", "repo", DefaultRenovateFilter(), FetchLimits{}, "github")
	require.NoError(t, err)
	assert.Empty(t, result.Requests)
}

func TestFetchPRs_APIError(t *testing.T) {
	mock := &mockPRService{
		handler: func(_ context.Context, _, _ string, _ *gh.PullRequestListOptions) ([]*gh.PullRequest, *gh.Response, error) {
			return nil, nil, fmt.Errorf("API rate limit exceeded")
		},
	}

	_, err := FetchPRs(context.Background(), mock, "test", "repo", DefaultRenovateFilter(), FetchLimits{}, "github")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list pull requests")
}

func TestFetchPRs_NilFields(t *testing.T) {
	mock := &mockPRService{
		handler: func(_ context.Context, _, _ string, _ *gh.PullRequestListOptions) ([]*gh.PullRequest, *gh.Response, error) {
			return []*gh.PullRequest{
				{
					Number: ptr(5),
					Title:  nil,
					Body:   nil,
					Head:   nil,
					Labels: []*gh.Label{{Name: ptr("renovate")}},
				},
			}, &gh.Response{}, nil
		},
	}

	result, err := FetchPRs(context.Background(), mock, "test", "repo", DefaultRenovateFilter(), FetchLimits{}, "github")
	require.NoError(t, err)
	require.Len(t, result.Requests, 1)
	assert.Equal(t, "", result.Requests[0].Title)
	assert.Equal(t, "", result.Requests[0].Description)
	assert.Equal(t, "", result.Requests[0].Branch)
}

func TestFetchPRs_NilCreatedAt(t *testing.T) {
	mock := &mockPRService{
		handler: func(_ context.Context, _, _ string, _ *gh.PullRequestListOptions) ([]*gh.PullRequest, *gh.Response, error) {
			return []*gh.PullRequest{
				{
					Number:    ptr(6),
					Title:     ptr("Update dependency lodash to v4.18.0"),
					CreatedAt: nil,
					Labels:    []*gh.Label{{Name: ptr("renovate")}},
					Head:      &gh.PullRequestBranch{Ref: ptr("renovate/lodash-4.18.0")},
				},
			}, &gh.Response{}, nil
		},
	}

	result, err := FetchPRs(context.Background(), mock, "test", "repo", DefaultRenovateFilter(), FetchLimits{}, "github")
	require.NoError(t, err)
	require.Len(t, result.Requests, 1)
	assert.Equal(t, "Update dependency lodash to v4.18.0", result.Requests[0].Title)
	assert.True(t, result.Requests[0].CreatedAt.IsZero())
}

func TestFetchPRs_Pagination(t *testing.T) {
	callCount := 0
	mock := &mockPRService{
		handler: func(_ context.Context, _, _ string, opts *gh.PullRequestListOptions) ([]*gh.PullRequest, *gh.Response, error) {
			callCount++
			if callCount == 1 {
				return []*gh.PullRequest{
					{
						Number: ptr(1),
						Title:  ptr("Update dependency lodash to v4.18.1"),
						Labels: []*gh.Label{{Name: ptr("renovate")}},
						Head:   &gh.PullRequestBranch{Ref: ptr("renovate/lodash-4.18.1")},
					},
				}, &gh.Response{NextPage: 2}, nil
			}
			return []*gh.PullRequest{
				{
					Number: ptr(2),
					Title:  ptr("Update dependency axios to v1.0.0"),
					Labels: []*gh.Label{{Name: ptr("renovate")}},
					Head:   &gh.PullRequestBranch{Ref: ptr("renovate/axios-1.0.0")},
				},
			}, &gh.Response{NextPage: 0}, nil
		},
	}

	result, err := FetchPRs(context.Background(), mock, "test", "repo", DefaultRenovateFilter(), FetchLimits{}, "github")
	require.NoError(t, err)
	require.Len(t, result.Requests, 2)
	assert.Equal(t, "Update dependency lodash to v4.18.1", result.Requests[0].Title)
	assert.Equal(t, "Update dependency axios to v1.0.0", result.Requests[1].Title)
	assert.Equal(t, 2, callCount)
}

func TestSplitRepo_Valid(t *testing.T) {
	owner, repo, err := splitGithubRepo("verophi/verophi")
	assert.NoError(t, err)
	assert.Equal(t, "verophi", owner)
	assert.Equal(t, "verophi", repo)
}

func TestSplitRepo_Invalid(t *testing.T) {
	tests := []string{"", "noslash", "/nope", "nope/"}
	for _, input := range tests {
		_, _, err := splitGithubRepo(input)
		assert.Error(t, err, "expected error for %q", input)
		assert.Contains(t, err.Error(), "repository name must be in owner/repo format")
	}
}

func TestNewGitHubClient_AllowsEmptyToken(t *testing.T) {
	assert.NotNil(t, newGitHubClient(""))
	assert.NotNil(t, newGitHubClient("token"))
}

func TestNormalizeFilter_DefaultsMissingValues(t *testing.T) {
	filter := normalizeFilter(ChangeRequestFilter{})

	assert.Equal(t, "renovate", filter.Label)
	assert.Equal(t, "renovate/", filter.BranchPrefix)
}

func TestDerefInt_Nil(t *testing.T) {
	assert.Equal(t, 0, derefInt(nil))
}

func TestClassifyGitHubError_RateLimit(t *testing.T) {
	err := classifyGitHubError(&gh.RateLimitError{}, "")

	require.Error(t, err)
	assert.Equal(t, "GitHub API rate limit exceeded. Pass --github-token to authenticate.", err.Error())
}

func TestClassifyGitHubError_PrivateRepoWithoutToken(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			err := classifyGitHubError(&gh.ErrorResponse{
				Response: &http.Response{StatusCode: status},
			}, "")

			require.Error(t, err)
			assert.Equal(t, "This repo requires authentication. Pass --github-token.", err.Error())
		})
	}
}

func TestClassifyGitHubError_DoesNotClassifyAuthenticatedErrors(t *testing.T) {
	original := &gh.ErrorResponse{
		Response: &http.Response{StatusCode: http.StatusForbidden},
	}

	err := classifyGitHubError(original, "token")

	assert.Same(t, original, err)
}

func TestClassifyGitHubError_DoesNotClassifyUnknownErrors(t *testing.T) {
	original := errors.New("boom")

	err := classifyGitHubError(original, "")

	assert.Same(t, original, err)
}

func TestClassifyGitHubError_DoesNotClassifyResponsesWithoutStatus(t *testing.T) {
	original := &gh.ErrorResponse{}

	err := classifyGitHubError(original, "")

	assert.Same(t, original, err)
}

func TestMatchesPR_CaseInsensitiveLabel(t *testing.T) {
	tests := []struct {
		label string
		want  bool
	}{
		{"renovate", true},
		{"Renovate", true},
		{"RENOVATE", true},
		{"ReNoVaTe", true},
		{"other", false},
	}

	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			pr := &gh.PullRequest{
				Labels: []*gh.Label{{Name: ptr(tt.label)}},
				Head:   &gh.PullRequestBranch{Ref: ptr("feature/unrelated")},
			}
			got := matchesPR(pr, ChangeRequestFilter{Label: "renovate", BranchPrefix: "renovate/"})
			assert.Equal(t, tt.want, got)
		})
	}
}
