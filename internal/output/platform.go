package output

import "fmt"

// Platform provides platform-specific presentation (noun, id prefix, URL shape).
type Platform interface {
	Noun() string
	Abbrev() string
	IDLabel(n int) string
}

type gitlabPresenter struct{}

func (gitlabPresenter) Noun() string         { return "merge request" }
func (gitlabPresenter) Abbrev() string       { return "MR" }
func (gitlabPresenter) IDLabel(n int) string { return fmt.Sprintf("!%d", n) }

type githubPresenter struct{}

func (githubPresenter) Noun() string         { return "pull request" }
func (githubPresenter) Abbrev() string       { return "PR" }
func (githubPresenter) IDLabel(n int) string { return fmt.Sprintf("#%d", n) }

// ForPlatform returns the Platform presenter for the given platform string.
func ForPlatform(platform string) Platform {
	switch platform {
	case "github":
		return githubPresenter{}
	default:
		return gitlabPresenter{}
	}
}
