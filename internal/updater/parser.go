package updater

import (
	"regexp"
	"strings"
)

var commonPrefixPattern = regexp.MustCompile(`^[=~^><v\s]+`)
var semverExtractPattern = regexp.MustCompile(`(\d+(?:\.\d+)*)(?:[-+][a-zA-Z0-9.]+)?`)

// stripVersionPrefix extracts a clean version string from prefixed formats.
func stripVersionPrefix(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	stripped := strings.TrimSpace(commonPrefixPattern.ReplaceAllString(v, ""))
	if len(stripped) > 0 && stripped[0] >= '0' && stripped[0] <= '9' {
		return stripped
	}
	match := semverExtractPattern.FindString(v)
	if match != "" {
		return match
	}
	return v
}

var titlePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^Update\s+dependency\s+(.+?)\s+to\s+v?(.+)$`),
	regexp.MustCompile(`(?i)^chore\(deps\):\s+update\s+(?:dependency\s+)?(.+?)\s+to\s+v?(.+)$`),
	regexp.MustCompile(`(?i)^fix\(deps\):\s+update\s+(?:dependency\s+)?(.+?)\s+to\s+v?(.+)$`),
	regexp.MustCompile(`(?i)^(?:chore|fix)\(deps\):\s+pin\s+(?:dependency\s+)?(.+?)\s+to\s+v?(.+)$`),
	regexp.MustCompile(`(?i)^Update\s+docker\s+image\s+(.+?)\s+to\s+v?(.+)$`),
	regexp.MustCompile(`(?i)^Update\s+(.+?)\s+to\s+v?(.+)$`),
}

func parseTitle(title string) (string, string, string) {
	for _, re := range titlePatterns {
		matches := re.FindStringSubmatch(title)
		if len(matches) >= 3 {
			dep := strings.TrimSpace(matches[1])
			to := strings.TrimSpace(matches[2])
			return dep, "", to
		}
	}
	return "", "", ""
}

var branchExactPattern = regexp.MustCompile(`^renovate/(.+?)-(\d+\.\d+\..+)$`)
var branchMajorPattern = regexp.MustCompile(`^renovate/(.+?)-(\d+)\.x(?:-lockfile)?$`)

func parseBranchName(branch string) (string, string, string) {
	matches := branchExactPattern.FindStringSubmatch(branch)
	if len(matches) >= 3 {
		return matches[1], "", matches[2]
	}
	matches = branchMajorPattern.FindStringSubmatch(branch)
	if len(matches) >= 3 {
		return matches[1], "", matches[2] + ".0.0"
	}
	return "", "", ""
}
