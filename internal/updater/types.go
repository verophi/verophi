package updater

import "github.com/verophi/verophi/pkg/model"

// ParserInput carries the data needed to extract changes from a single source
// change request. It is a struct (not only description/title/branch) so a future
// Dependabot adapter can parse files or metadata.
type ParserInput struct {
	Description string
	Title       string
	Branch      string
	Number      int
	URL         string
	Labels      []string
}

// Parser extracts typed changes from a change request input. The second return
// value is the number of dependency rows that were recognized (by name) but
// whose target version/digest could not be parsed.
type Parser interface {
	ExtractChanges(in ParserInput) ([]model.Change, int)
}
