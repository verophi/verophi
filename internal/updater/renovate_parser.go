package updater

import (
	"regexp"
	"strings"

	"github.com/verophi/verophi/pkg/model"
)

// descVersionPattern matches version transitions in Renovate PR tables.
// e.g. `1.2.3` → `1.2.4` or `~1.0` → `~1.1` (handles v/~/^/>=/tags/ prefixes)
var descVersionPattern = regexp.MustCompile("`\"?((?:tags/|[=~^><v ]*)\\d[^`]*?)\"?`\\s*→\\s*`\"?((?:tags/|[=~^><v ]*)\\d[^`]*?)\"?`")

// descPackagePattern matches linked package names in Renovate tables.
// e.g. | [lodash](https://npmjs.com/lodash) | in a markdown table row
var descPackagePattern = regexp.MustCompile(`\|\s*\[([^\]]+)\]`)

// descPackagePatternPlain matches unlinked package names.
// e.g. | golang.org/x/net | in a table row without markdown link syntax
var descPackagePatternPlain = regexp.MustCompile(`\|\s*([a-zA-Z0-9@/_:.-]+)\s*\|`)

// descUpdateTypePattern matches the Update column including the extended types.
// e.g. | minor | or | pinDigest | in the update-type column of a Renovate table
var descUpdateTypePattern = regexp.MustCompile(`\|\s*(major|minor|patch|pin|pinDigest|bump|digest|rollback|replacement|lockFileMaintenance)\s*\|`)

// digestToPattern / digestFromPattern capture the backtick-quoted tokens around
// the arrow in a digest row, e.g. "→ `fb4cd12`" (no from) or "`old` → `new`".
// Digest targets are SHAs, not semvers, so descVersionPattern (digit-anchored)
// skips them; these recover the token so the change is still surfaced.
var digestToPattern = regexp.MustCompile("→\\s*`([^`]+)`")
var digestFromPattern = regexp.MustCompile("`([^`]+)`\\s*→")

// RenovateParser extracts changes from Renovate-style change requests.
type RenovateParser struct{}

func (p RenovateParser) ExtractChanges(in ParserInput) ([]model.Change, int) {
	results, unparsed := extractParseResults(in.Description, in.Title, in.Branch)
	changes := make([]model.Change, 0, len(results))
	for _, r := range results {
		changes = append(changes, model.Change{
			DependencyName: r.DependencyName,
			CurrentVersion: r.CurrentVersion,
			TargetVersion:  r.TargetVersion,
			ChangeType:     mapUpdateType(r.UpdateType),
		})
	}
	return changes, unparsed
}

// isDigestUpdate reports whether an update type carries a digest (SHA) target
// rather than a semantic version.
func isDigestUpdate(ut string) bool {
	switch strings.ToLower(ut) {
	case "pindigest", "digest":
		return true
	}
	return false
}

// parseDigestChange extracts the from/to digest tokens from a digest row.
func parseDigestChange(line string) (from, to string) {
	if m := digestToPattern.FindStringSubmatch(line); len(m) >= 2 {
		to = strings.TrimSpace(m[1])
	}
	if m := digestFromPattern.FindStringSubmatch(line); len(m) >= 2 {
		from = strings.TrimSpace(m[1])
	}
	return from, to
}

// mapUpdateType maps a Renovate updateType string to a model.ChangeType.
func mapUpdateType(ut string) model.ChangeType {
	switch strings.ToLower(ut) {
	case "major":
		return model.ChangeMajor
	case "minor":
		return model.ChangeMinor
	case "patch":
		return model.ChangePatch
	case "pin":
		return model.ChangePin
	case "pindigest":
		return model.ChangePinDigest
	case "bump":
		return model.ChangeBump
	case "digest":
		return model.ChangeDigest
	case "rollback":
		return model.ChangeRollback
	case "replacement":
		return model.ChangeReplacement
	case "lockfilemaintenance":
		return model.ChangeMaintenance
	default:
		return model.ChangeUnknown
	}
}

// parseResult is the internal intermediate representation.
type parseResult struct {
	DependencyName string
	CurrentVersion string
	TargetVersion  string
	UpdateType     string
}

func extractParseResults(description, title, branch string) ([]parseResult, int) {
	deps, unparsed := parseDescription(description)
	if len(deps) > 0 {
		return deps, unparsed
	}
	dep, from, to := parseTitle(title)
	if dep != "" {
		return []parseResult{{DependencyName: dep, CurrentVersion: from, TargetVersion: to}}, 0
	}
	dep, from, to = parseBranchName(branch)
	if dep != "" {
		return []parseResult{{DependencyName: dep, CurrentVersion: from, TargetVersion: to}}, 0
	}
	return nil, unparsed
}

func parseDescription(desc string) ([]parseResult, int) {
	if desc == "" {
		return nil, 0
	}
	var results []parseResult
	unparsed := 0
	for _, line := range strings.Split(desc, "\n") {
		// Only table rows with a version arrow (U+2192 "→") are dependency lines.
		if !strings.Contains(line, "|") || !strings.Contains(line, "\u2192") {
			continue
		}
		// FindStringSubmatch returns [fullMatch, group1, ...]; len>=2 means the
		// capture group matched a package name.
		pkgMatch := descPackagePattern.FindStringSubmatch(line)
		if len(pkgMatch) < 2 {
			pkgMatch = descPackagePatternPlain.FindStringSubmatch(line)
			if len(pkgMatch) < 2 {
				continue
			}
		}
		name := strings.TrimSpace(pkgMatch[1])

		var updateType string
		if m := descUpdateTypePattern.FindStringSubmatch(line); len(m) >= 2 {
			updateType = m[1]
		}

		var from, to string
		if verMatch := descVersionPattern.FindStringSubmatch(line); len(verMatch) >= 3 {
			from = stripVersionPrefix(verMatch[1])
			to = stripVersionPrefix(verMatch[2])
		} else if isDigestUpdate(updateType) {
			from, to = parseDigestChange(line)
		}

		switch {
		case name != "" && to != "":
			results = append(results, parseResult{
				DependencyName: name,
				CurrentVersion: from,
				TargetVersion:  to,
				UpdateType:     updateType,
			})
		case name != "":
			// recognized a dependency row by name but could not parse a target
			// version or digest from it; count it so grouped requests surface the gap.
			unparsed++
		}
	}
	return results, unparsed
}
