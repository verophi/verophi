package platform

import (
	"context"
	"testing"
	"time"

	gh "github.com/google/go-github/v85/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gitlab "gitlab.com/gitlab-org/api/client-go"
	gitlabtesting "gitlab.com/gitlab-org/api/client-go/testing"
	"go.uber.org/mock/gomock"
)

func TestFetchPRs_TruncatesAtMaxRequests(t *testing.T) {
	prsPerPage := 3
	maxAllowed := 5

	pageCount := 0
	service := &mockPRService{
		handler: func(_ context.Context, _, _ string, _ *gh.PullRequestListOptions) ([]*gh.PullRequest, *gh.Response, error) {
			pageCount++
			page := makePRPage(prsPerPage, pageCount)
			return page, &gh.Response{NextPage: pageCount + 1}, nil
		},
	}

	result, err := FetchPRs(context.Background(), service, "org", "repo", DefaultRenovateFilter(), FetchLimits{MaxRequests: maxAllowed}, "github")
	require.NoError(t, err)

	assert.True(t, result.Truncated)
	assert.Equal(t, maxAllowed, result.Checked)
	assert.LessOrEqual(t, len(result.Requests), maxAllowed)
}

func TestFetchPRs_NotTruncatedWhenBelowLimit(t *testing.T) {
	service := &mockPRService{
		handler: func(_ context.Context, _, _ string, _ *gh.PullRequestListOptions) ([]*gh.PullRequest, *gh.Response, error) {
			return []*gh.PullRequest{
				{Number: ptr(1), Title: ptr("Update lodash"), Labels: []*gh.Label{{Name: ptr("renovate")}}, Head: &gh.PullRequestBranch{Ref: ptr("renovate/lodash-4.x")}},
			}, &gh.Response{}, nil
		},
	}

	result, err := FetchPRs(context.Background(), service, "org", "repo", DefaultRenovateFilter(), FetchLimits{MaxRequests: 100}, "github")
	require.NoError(t, err)

	assert.False(t, result.Truncated)
	assert.Equal(t, 1, result.Checked)
}

func TestFetchMRs_TruncatesAtMaxRequests(t *testing.T) {
	prsPerPage := 3
	maxAllowed := 5

	ctrl := gomock.NewController(t)
	service := gitlabtesting.NewMockMergeRequestsServiceInterface(ctrl)

	pageCount := 0
	service.EXPECT().
		ListProjectMergeRequests("12345", gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ any, _ *gitlab.ListProjectMergeRequestsOptions, _ ...gitlab.RequestOptionFunc) ([]*gitlab.BasicMergeRequest, *gitlab.Response, error) {
			pageCount++
			page := makeMRPage(prsPerPage, pageCount)
			return page, &gitlab.Response{NextPage: int64(pageCount + 1)}, nil
		}).Times(2)

	result, err := FetchMRs(context.Background(), service, "12345", DefaultRenovateFilter(), FetchLimits{MaxRequests: maxAllowed}, "gitlab")
	require.NoError(t, err)

	assert.True(t, result.Truncated)
	assert.Equal(t, maxAllowed, result.Checked)
}

func TestFetchMRs_NotTruncatedWhenBelowLimit(t *testing.T) {
	ctrl := gomock.NewController(t)
	service := gitlabtesting.NewMockMergeRequestsServiceInterface(ctrl)

	service.EXPECT().
		ListProjectMergeRequests("12345", gomock.Any(), gomock.Any()).
		Return([]*gitlab.BasicMergeRequest{
			{IID: 1, Title: "Update lodash", Labels: gitlab.Labels{"renovate"}, SourceBranch: "renovate/lodash-4.x"},
		}, &gitlab.Response{}, nil)

	result, err := FetchMRs(context.Background(), service, "12345", DefaultRenovateFilter(), FetchLimits{MaxRequests: 100}, "gitlab")
	require.NoError(t, err)

	assert.False(t, result.Truncated)
	assert.Equal(t, 1, result.Checked)
}

func TestFetchLimits_Defaults(t *testing.T) {
	assert.Equal(t, DefaultMaxRequests, FetchLimits{}.effectiveMaxRequests())
	assert.Equal(t, DefaultMaxRequests, FetchLimits{MaxRequests: -1}.effectiveMaxRequests())
	assert.Equal(t, 500, FetchLimits{MaxRequests: 500}.effectiveMaxRequests())
}

func TestFetchPRs_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	service := &mockPRService{
		handler: func(ctx context.Context, _, _ string, _ *gh.PullRequestListOptions) ([]*gh.PullRequest, *gh.Response, error) {
			return nil, nil, ctx.Err()
		},
	}

	_, err := FetchPRs(ctx, service, "org", "repo", DefaultRenovateFilter(), FetchLimits{}, "github")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

func TestFetchPRs_ContextTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	time.Sleep(5 * time.Millisecond)

	service := &mockPRService{
		handler: func(ctx context.Context, _, _ string, _ *gh.PullRequestListOptions) ([]*gh.PullRequest, *gh.Response, error) {
			return nil, nil, ctx.Err()
		},
	}

	_, err := FetchPRs(ctx, service, "org", "repo", DefaultRenovateFilter(), FetchLimits{}, "github")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "deadline exceeded")
}

func TestFetchMRs_ContextCancelled(t *testing.T) {
	ctrl := gomock.NewController(t)
	service := gitlabtesting.NewMockMergeRequestsServiceInterface(ctrl)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	service.EXPECT().
		ListProjectMergeRequests("12345", gomock.Any(), gomock.Any()).
		Return(nil, nil, ctx.Err())

	_, err := FetchMRs(ctx, service, "12345", DefaultRenovateFilter(), FetchLimits{}, "gitlab")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

// makePRPage generates a page of renovate-labeled PRs for testing pagination.
func makePRPage(count, pageNumber int) []*gh.PullRequest {
	prs := make([]*gh.PullRequest, count)
	for i := range prs {
		n := (pageNumber-1)*count + i + 1
		prs[i] = &gh.PullRequest{
			Number: ptr(n),
			Title:  ptr("Update dependency"),
			Labels: []*gh.Label{{Name: ptr("renovate")}},
			Head:   &gh.PullRequestBranch{Ref: ptr("renovate/dep")},
		}
	}
	return prs
}

// makeMRPage generates a page of renovate-labeled MRs for testing pagination.
func makeMRPage(count, pageNumber int) []*gitlab.BasicMergeRequest {
	mrs := make([]*gitlab.BasicMergeRequest, count)
	for i := range mrs {
		n := (pageNumber-1)*count + i + 1
		created := time.Now()
		mrs[i] = &gitlab.BasicMergeRequest{
			IID:          int64(n),
			Title:        "Update dependency",
			Labels:       gitlab.Labels{"renovate"},
			SourceBranch: "renovate/dep",
			CreatedAt:    &created,
		}
	}
	return mrs
}
