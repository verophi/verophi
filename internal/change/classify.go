package change

import (
	"github.com/verophi/verophi/internal/semver"
	"github.com/verophi/verophi/pkg/model"
)

// classifyFromVersions derives a ChangeType from the version transition when the
// updater did not supply one (a Renovate table without an Update column). It is
// a deliberately thin semver trichotomy, not an ecosystem-aware comparison; when
// either version cannot be parsed it stays ChangeUnknown rather than guessing.
func classifyFromVersions(current, target string) model.ChangeType {
	if current == "" || target == "" {
		return model.ChangeUnknown
	}
	from, err := semver.Parse(current)
	if err != nil {
		return model.ChangeUnknown
	}
	to, err := semver.Parse(target)
	if err != nil {
		return model.ChangeUnknown
	}
	if to.Major > from.Major {
		return model.ChangeMajor
	}
	if to.Major == from.Major && to.Minor > from.Minor {
		return model.ChangeMinor
	}
	return model.ChangePatch
}
