package platform

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	gh "github.com/google/go-github/v85/github"
)

type PullRequestLister interface {
	List(ctx context.Context, owner, repo string, opts *gh.PullRequestListOptions) ([]*gh.PullRequest, *gh.Response, error)
}

var _ PullRequestLister = (*gh.PullRequestsService)(nil)

func ReadGithubPRs(ctx context.Context, opts ReadOptions) (ReadResult, error) {
	owner, repo, err := splitGithubRepo(opts.Repository)
	if err != nil {
		return ReadResult{}, err
	}
	client := newGitHubClient(opts.Token)
	result, fetchErr := FetchPRs(ctx, client.PullRequests, owner, repo, opts.Filter, opts.Limits, opts.PlatformTag)
	if fetchErr != nil {
		return ReadResult{}, classifyGitHubError(fetchErr, opts.Token)
	}
	return result, nil
}

func FetchPRs(ctx context.Context, service PullRequestLister, owner, repo string, filter ChangeRequestFilter, limits FetchLimits, platformTag string) (ReadResult, error) {
	filter = normalizeFilter(filter)
	maxRequests := limits.effectiveMaxRequests()
	opts := &gh.PullRequestListOptions{
		State: "open",
		ListOptions: gh.ListOptions{
			PerPage: 100,
			Page:    1,
		},
	}

	var allPRs []*gh.PullRequest
	truncated := false
	for {
		prs, resp, err := service.List(ctx, owner, repo, opts)
		if err != nil {
			return ReadResult{}, fmt.Errorf("failed to list pull requests for %s/%s: %w", owner, repo, err)
		}
		allPRs = append(allPRs, prs...)

		if len(allPRs) >= maxRequests {
			allPRs = allPRs[:maxRequests]
			truncated = true
			break
		}

		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	var requests []ChangeRequestRaw
	for _, pr := range allPRs {
		if !matchesPR(pr, filter) {
			continue
		}

		var createdAt time.Time
		if pr.CreatedAt != nil {
			createdAt = pr.CreatedAt.Time
		}

		var labels []string
		for _, l := range pr.Labels {
			if l.Name != nil {
				labels = append(labels, *l.Name)
			}
		}

		title := derefStr(pr.Title)
		body := derefStr(pr.Body)
		branch := ""
		if pr.Head != nil {
			branch = derefStr(pr.Head.Ref)
		}

		requests = append(requests, ChangeRequestRaw{
			Number:      derefInt(pr.Number),
			URL:         derefStr(pr.HTMLURL),
			Title:       title,
			Platform:    platformTag,
			Labels:      labels,
			CreatedAt:   createdAt,
			Description: body,
			Branch:      branch,
		})
	}

	return ReadResult{Requests: requests, Checked: len(allPRs), Truncated: truncated}, nil
}

func matchesPR(pr *gh.PullRequest, filter ChangeRequestFilter) bool {
	for _, label := range pr.Labels {
		if label.Name != nil && strings.EqualFold(*label.Name, filter.Label) {
			return true
		}
	}
	if pr.Head != nil && pr.Head.Ref != nil {
		if strings.HasPrefix(*pr.Head.Ref, filter.BranchPrefix) {
			return true
		}
	}
	return false
}

func splitGithubRepo(repo string) (owner, name string, err error) {
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("repository name must be in owner/repo format, got %q", repo)
	}
	return parts[0], parts[1], nil
}

func newGitHubClient(token string) *gh.Client {
	client := gh.NewClient(nil)
	if token == "" {
		return client
	}
	return client.WithAuthToken(token)
}

func classifyGitHubError(err error, token string) error {
	if _, ok := errors.AsType[*gh.RateLimitError](err); ok {
		return &RateLimitExceededError{Message: "GitHub API rate limit exceeded. Pass --github-token to authenticate."}
	}

	var errResp *gh.ErrorResponse
	if token == "" && errors.As(err, &errResp) && errResp.Response != nil {
		switch errResp.Response.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return &AuthenticationRequiredError{Message: "This repo requires authentication. Pass --github-token."}
		}
	}

	return err
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefInt(i *int) int {
	if i == nil {
		return 0
	}
	return *i
}
