package change

import (
	"github.com/verophi/verophi/internal/platform"
	"github.com/verophi/verophi/internal/updater"
	"github.com/verophi/verophi/pkg/model"
)

// Build constructs one ChangeRequest per source request, one Change per dependency.
// Status is set to parsed or unparsed; correlation promotes it later.
func Build(raw []platform.ChangeRequestRaw, parser updater.Parser) []model.ChangeRequest {
	requests := make([]model.ChangeRequest, 0, len(raw))
	for _, r := range raw {
		changes, unparsedDeps := parser.ExtractChanges(updater.ParserInput{
			Description: r.Description,
			Title:       r.Title,
			Branch:      r.Branch,
			Number:      r.Number,
			URL:         r.URL,
			Labels:      r.Labels,
		})

		cr := model.ChangeRequest{
			Number:       r.Number,
			URL:          r.URL,
			Title:        r.Title,
			Platform:     r.Platform,
			CreatedAt:    r.CreatedAt,
			Labels:       r.Labels,
			UnparsedDeps: unparsedDeps,
		}

		if len(changes) == 0 {
			cr.Status = model.StatusUnparsed
		} else {
			cr.Status = model.StatusParsed
			assessments := make([]model.ChangeAssessment, 0, len(changes))
			for _, c := range changes {
				if c.ChangeType == model.ChangeUnknown {
					c.ChangeType = classifyFromVersions(c.CurrentVersion, c.TargetVersion)
				}
				assessments = append(assessments, model.ChangeAssessment{
					Change: c,
				})
			}
			cr.Assessments = assessments
		}

		requests = append(requests, cr)
	}
	return requests
}
