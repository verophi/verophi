package platform

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gitlab "gitlab.com/gitlab-org/api/client-go"
	gitlabtesting "gitlab.com/gitlab-org/api/client-go/testing"
	"go.uber.org/mock/gomock"
)

func TestFetchMRs_BasicFlow(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := gitlabtesting.NewMockMergeRequestsServiceInterface(ctrl)

	createdAt := time.Now().Add(-48 * time.Hour)
	mock.EXPECT().
		ListProjectMergeRequests("12345", gomock.Any(), gomock.Any()).
		Return([]*gitlab.BasicMergeRequest{
			{
				IID:          1,
				Title:        "fix(deps): update dependency lodash to v4.18.1",
				Description:  "| [lodash](https://lodash.com) | [`4.17.20` → `4.18.1`](https://example.com) |",
				Labels:       gitlab.Labels{"renovate", "minor"},
				SourceBranch: "renovate/lodash-4.18.1",
				WebURL:       "https://gitlab.com/test/-/merge_requests/1",
				CreatedAt:    &createdAt,
			},
		}, &gitlab.Response{}, nil)

	result, err := FetchMRs(context.Background(), mock, "12345", DefaultRenovateFilter(), FetchLimits{}, "gitlab")
	require.NoError(t, err)
	require.Len(t, result.Requests, 1)

	input := result.Requests[0]
	assert.Equal(t, "| [lodash](https://lodash.com) | [`4.17.20` → `4.18.1`](https://example.com) |", input.Description)
	assert.Equal(t, "fix(deps): update dependency lodash to v4.18.1", input.Title)
	assert.Equal(t, "renovate/lodash-4.18.1", input.Branch)
	assert.Equal(t, 1, input.Number)
	assert.Equal(t, "https://gitlab.com/test/-/merge_requests/1", input.URL)
	assert.Equal(t, "gitlab", input.Platform)
	assert.Equal(t, createdAt, input.CreatedAt)
	assert.Equal(t, []string{"renovate", "minor"}, input.Labels)
}

func TestFetchMRs_MultipleInputs(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := gitlabtesting.NewMockMergeRequestsServiceInterface(ctrl)

	mock.EXPECT().
		ListProjectMergeRequests("12345", gomock.Any(), gomock.Any()).
		Return([]*gitlab.BasicMergeRequest{
			{
				IID:          1,
				Title:        "feat: add new feature",
				Labels:       gitlab.Labels{"feature"},
				SourceBranch: "feature/new-thing",
			},
			{
				IID:          2,
				Title:        "fix(deps): update dependency axios to v1.0.0",
				Labels:       gitlab.Labels{"renovate"},
				SourceBranch: "renovate/axios-1.x",
				Description:  "| [axios](https://axios-http.com) | [`0.21.1` → `1.0.0`](https://example.com) |",
			},
		}, &gitlab.Response{}, nil)

	result, err := FetchMRs(context.Background(), mock, "12345", DefaultRenovateFilter(), FetchLimits{}, "gitlab")
	require.NoError(t, err)
	require.Len(t, result.Requests, 1)
	assert.Equal(t, "fix(deps): update dependency axios to v1.0.0", result.Requests[0].Title)
}

func TestFetchMRs_CustomLabel(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := gitlabtesting.NewMockMergeRequestsServiceInterface(ctrl)

	mock.EXPECT().
		ListProjectMergeRequests("12345", gomock.Any(), gomock.Any()).
		Return([]*gitlab.BasicMergeRequest{
			{
				IID:          2,
				Title:        "fix(deps): update dependency axios to v1.0.0",
				Labels:       gitlab.Labels{"custom-bot"},
				SourceBranch: "bot/axios-1.x",
			},
		}, &gitlab.Response{}, nil)

	result, err := FetchMRs(context.Background(), mock, "12345", ChangeRequestFilter{
		Label:        "custom-bot",
		BranchPrefix: "renovate/",
	}, FetchLimits{}, "gitlab")
	require.NoError(t, err)
	require.Len(t, result.Requests, 1)
	assert.Equal(t, 1, result.Checked)
	assert.Equal(t, "fix(deps): update dependency axios to v1.0.0", result.Requests[0].Title)
}

func TestFetchMRs_CustomBranchPrefix(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := gitlabtesting.NewMockMergeRequestsServiceInterface(ctrl)

	mock.EXPECT().
		ListProjectMergeRequests("12345", gomock.Any(), gomock.Any()).
		Return([]*gitlab.BasicMergeRequest{
			{
				IID:          2,
				Title:        "fix(deps): update dependency axios to v1.0.0",
				Labels:       gitlab.Labels{"deps"},
				SourceBranch: "bot/axios-1.x",
			},
		}, &gitlab.Response{}, nil)

	result, err := FetchMRs(context.Background(), mock, "12345", ChangeRequestFilter{
		Label:        "renovate",
		BranchPrefix: "bot/",
	}, FetchLimits{}, "gitlab")
	require.NoError(t, err)
	require.Len(t, result.Requests, 1)
	assert.Equal(t, "bot/axios-1.x", result.Requests[0].Branch)
}

func TestFetchMRs_GroupedMR(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := gitlabtesting.NewMockMergeRequestsServiceInterface(ctrl)

	desc := "| [lodash](https://lodash.com) | [`4.17.20` → `4.17.21`](https://example.com) |\n" +
		"| [express](https://expressjs.com) | [`4.17.1` → `4.17.3`](https://example.com) |"

	mock.EXPECT().
		ListProjectMergeRequests("12345", gomock.Any(), gomock.Any()).
		Return([]*gitlab.BasicMergeRequest{
			{
				IID:          5,
				Title:        "fix(deps): update all patch dependencies",
				Labels:       gitlab.Labels{"renovate", "patch"},
				SourceBranch: "renovate/patch-all-patch",
				Description:  desc,
			},
		}, &gitlab.Response{}, nil)

	result, err := FetchMRs(context.Background(), mock, "12345", DefaultRenovateFilter(), FetchLimits{}, "gitlab")
	require.NoError(t, err)
	require.Len(t, result.Requests, 1)
	assert.Equal(t, desc, result.Requests[0].Description)
	assert.Equal(t, 5, result.Requests[0].Number)
}

func TestFetchMRs_EmptyResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := gitlabtesting.NewMockMergeRequestsServiceInterface(ctrl)

	mock.EXPECT().
		ListProjectMergeRequests("12345", gomock.Any(), gomock.Any()).
		Return([]*gitlab.BasicMergeRequest{}, &gitlab.Response{}, nil)

	result, err := FetchMRs(context.Background(), mock, "12345", DefaultRenovateFilter(), FetchLimits{}, "gitlab")
	require.NoError(t, err)
	assert.Empty(t, result.Requests)
}

func TestFetchMRs_APIError(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := gitlabtesting.NewMockMergeRequestsServiceInterface(ctrl)

	mock.EXPECT().
		ListProjectMergeRequests("12345", gomock.Any(), gomock.Any()).
		Return(nil, nil, assert.AnError)

	_, err := FetchMRs(context.Background(), mock, "12345", DefaultRenovateFilter(), FetchLimits{}, "gitlab")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list merge requests")
}

func TestFetchMRs_LockFileMaintenance(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := gitlabtesting.NewMockMergeRequestsServiceInterface(ctrl)

	mock.EXPECT().
		ListProjectMergeRequests("12345", gomock.Any(), gomock.Any()).
		Return([]*gitlab.BasicMergeRequest{
			{
				IID:          10,
				Title:        "Lock file maintenance",
				Labels:       gitlab.Labels{"renovate", "lockfile"},
				SourceBranch: "renovate/lock-file-maintenance",
				Description:  "This MR regenerates the lock file.",
			},
		}, &gitlab.Response{}, nil)

	result, err := FetchMRs(context.Background(), mock, "12345", DefaultRenovateFilter(), FetchLimits{}, "gitlab")
	require.NoError(t, err)
	require.Len(t, result.Requests, 1)
	assert.Equal(t, "Lock file maintenance", result.Requests[0].Title)
}

func TestFetchMRs_NullFields(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := gitlabtesting.NewMockMergeRequestsServiceInterface(ctrl)

	mock.EXPECT().
		ListProjectMergeRequests("12345", gomock.Any(), gomock.Any()).
		Return([]*gitlab.BasicMergeRequest{
			{
				IID:          3,
				Title:        "Update dependency lodash to v4.18.0",
				Labels:       gitlab.Labels{"renovate"},
				SourceBranch: "renovate/lodash-4.18.0",
				CreatedAt:    nil,
				Description:  "",
			},
		}, &gitlab.Response{}, nil)

	result, err := FetchMRs(context.Background(), mock, "12345", DefaultRenovateFilter(), FetchLimits{}, "gitlab")
	require.NoError(t, err)
	require.Len(t, result.Requests, 1)
	assert.Equal(t, "Update dependency lodash to v4.18.0", result.Requests[0].Title)
	assert.Equal(t, "renovate/lodash-4.18.0", result.Requests[0].Branch)
	assert.True(t, result.Requests[0].CreatedAt.IsZero())
}

func TestFetchMRs_Pagination(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := gitlabtesting.NewMockMergeRequestsServiceInterface(ctrl)

	callCount := 0
	mock.EXPECT().
		ListProjectMergeRequests("12345", gomock.Any(), gomock.Any()).
		DoAndReturn(func(pid any, opts *gitlab.ListProjectMergeRequestsOptions, options ...gitlab.RequestOptionFunc) ([]*gitlab.BasicMergeRequest, *gitlab.Response, error) {
			callCount++
			if callCount == 1 {
				return []*gitlab.BasicMergeRequest{
					{
						IID:          1,
						Title:        "Update dependency lodash to v4.18.1",
						Labels:       gitlab.Labels{"renovate"},
						SourceBranch: "renovate/lodash-4.18.1",
					},
				}, &gitlab.Response{NextPage: 2}, nil
			}
			return []*gitlab.BasicMergeRequest{
				{
					IID:          2,
					Title:        "Update dependency axios to v1.0.0",
					Labels:       gitlab.Labels{"renovate"},
					SourceBranch: "renovate/axios-1.x",
				},
			}, &gitlab.Response{NextPage: 0}, nil
		}).Times(2)

	result, err := FetchMRs(context.Background(), mock, "12345", DefaultRenovateFilter(), FetchLimits{}, "gitlab")
	require.NoError(t, err)
	require.Len(t, result.Requests, 2)
	assert.Equal(t, "Update dependency lodash to v4.18.1", result.Requests[0].Title)
	assert.Equal(t, "Update dependency axios to v1.0.0", result.Requests[1].Title)
}

func TestNewGitLabClient(t *testing.T) {
	defaultClient, err := newGitLabClient("", "https://gitlab.com")
	require.NoError(t, err)
	assert.NotNil(t, defaultClient)

	customClient, err := newGitLabClient("token", "https://gitlab.example.com")
	require.NoError(t, err)
	assert.NotNil(t, customClient)
}

func TestClassifyGitLabError_RateLimit(t *testing.T) {
	err := classifyGitLabError(&gitlab.ErrorResponse{
		Response: &http.Response{StatusCode: http.StatusTooManyRequests},
	}, "")

	require.Error(t, err)
	assert.Equal(t, "GitLab API rate limit exceeded. Pass --gitlab-token to authenticate.", err.Error())
}

func TestClassifyGitLabError_PrivateProjectWithoutToken(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			err := classifyGitLabError(&gitlab.ErrorResponse{
				Response: &http.Response{StatusCode: status},
			}, "")

			require.Error(t, err)
			assert.Equal(t, "This project requires authentication. Pass --gitlab-token.", err.Error())
		})
	}
}

func TestClassifyGitLabError_NotFoundWithoutToken(t *testing.T) {
	err := classifyGitLabError(gitlab.ErrNotFound, "")

	require.Error(t, err)
	assert.Equal(t, "This project requires authentication. Pass --gitlab-token.", err.Error())
}

func TestClassifyGitLabError_DoesNotClassifyAuthenticatedErrors(t *testing.T) {
	original := &gitlab.ErrorResponse{
		Response: &http.Response{StatusCode: http.StatusForbidden},
	}

	err := classifyGitLabError(original, "token")

	assert.Same(t, original, err)
}

func TestClassifyGitLabError_DoesNotClassifyUnknownErrors(t *testing.T) {
	original := errors.New("boom")

	err := classifyGitLabError(original, "")

	assert.Same(t, original, err)
}

func TestClassifyGitLabError_DoesNotClassifyResponsesWithoutStatus(t *testing.T) {
	original := &gitlab.ErrorResponse{}

	err := classifyGitLabError(original, "")

	assert.Same(t, original, err)
}
