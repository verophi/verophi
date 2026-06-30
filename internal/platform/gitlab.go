package platform

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func ReadGitlabMRs(ctx context.Context, opts ReadOptions) (ReadResult, error) {
	client, err := newGitLabClient(opts.Token, opts.BaseURL)
	if err != nil {
		return ReadResult{}, err
	}
	result, err := FetchMRs(ctx, client.MergeRequests, opts.Repository, opts.Filter, opts.Limits, opts.PlatformTag)
	if err != nil {
		return ReadResult{}, classifyGitLabError(err, opts.Token)
	}
	return result, nil
}

func FetchMRs(ctx context.Context, service gitlab.MergeRequestsServiceInterface, projectID string, filter ChangeRequestFilter, limits FetchLimits, platformTag string) (ReadResult, error) {
	filter = normalizeFilter(filter)
	maxRequests := limits.effectiveMaxRequests()
	listOpts := &gitlab.ListProjectMergeRequestsOptions{
		State: new("opened"),
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
			Page:    1,
		},
	}

	var allMRs []*gitlab.BasicMergeRequest
	truncated := false
	for {
		mrs, resp, err := service.ListProjectMergeRequests(projectID, listOpts, gitlab.WithContext(ctx))
		if err != nil {
			return ReadResult{}, fmt.Errorf("failed to list merge requests for project %s: %w", projectID, err)
		}
		allMRs = append(allMRs, mrs...)

		if len(allMRs) >= maxRequests {
			allMRs = allMRs[:maxRequests]
			truncated = true
			break
		}

		if resp == nil || resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	var requests []ChangeRequestRaw
	for _, mr := range allMRs {
		if !matchesMR(mr, filter) {
			continue
		}

		labels := make([]string, len(mr.Labels))
		copy(labels, mr.Labels)

		var createdAt time.Time
		if mr.CreatedAt != nil {
			createdAt = *mr.CreatedAt
		}

		requests = append(requests, ChangeRequestRaw{
			Number:      int(mr.IID),
			URL:         mr.WebURL,
			Title:       mr.Title,
			Platform:    platformTag,
			Labels:      labels,
			CreatedAt:   createdAt,
			Description: mr.Description,
			Branch:      mr.SourceBranch,
		})
	}
	return ReadResult{Requests: requests, Checked: len(allMRs), Truncated: truncated}, nil
}

func matchesMR(mr *gitlab.BasicMergeRequest, filter ChangeRequestFilter) bool {
	for _, label := range mr.Labels {
		if strings.EqualFold(label, filter.Label) {
			return true
		}
	}
	return strings.HasPrefix(mr.SourceBranch, filter.BranchPrefix)
}

func newGitLabClient(token, baseURL string) (*gitlab.Client, error) {
	var opts []gitlab.ClientOptionFunc
	if baseURL != "" && baseURL != "https://gitlab.com" {
		opts = append(opts, gitlab.WithBaseURL(baseURL))
	}
	return gitlab.NewClient(token, opts...)
}

func classifyGitLabError(err error, token string) error {
	if token == "" && errors.Is(err, gitlab.ErrNotFound) {
		return &AuthenticationRequiredError{Message: "This project requires authentication. Pass --gitlab-token."}
	}

	if errResp, ok := errors.AsType[*gitlab.ErrorResponse](err); ok && errResp.Response != nil {
		switch errResp.Response.StatusCode {
		case http.StatusTooManyRequests:
			return &RateLimitExceededError{Message: "GitLab API rate limit exceeded. Pass --gitlab-token to authenticate."}
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			if token == "" {
				return &AuthenticationRequiredError{Message: "This project requires authentication. Pass --gitlab-token."}
			}
		}
	}

	return err
}
