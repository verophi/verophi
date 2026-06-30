// Package normalize provides ecosystem-aware dependency name normalization
// for matching between Trivy SBOM output and Renovate change request data.
//
// Most ecosystems use identical naming between the two tools. Python is the
// notable exception: PEP 503 specifies that package names are compared
// case-insensitively and that runs of [-_.] are treated as equivalent.
// Renovate normalizes Python package names via this rule before writing them
// to PR descriptions.
//
// Maven is intentionally NOT special-cased here: matching a Maven coordinate
// against an artifactId-only SBOM name is done by PURL identity in the analysis
// (which preserves the groupId, R14.1), so collapsing to the artifactId here
// would reintroduce cross-groupId false matches.
package normalize

import (
	"regexp"
	"strings"
)

// pypiSeparators matches one or more consecutive hyphens, underscores, or dots.
var pypiSeparators = regexp.MustCompile(`[-_.]+`)

// DependencyName returns a normalized form of the dependency name suitable for
// comparison. For Python packages, PEP 503 normalization is applied: runs of
// [-_.] become a single hyphen and the result is lowercased. For every other
// ecosystem a simple lowercase is sufficient.
func DependencyName(name, ecosystem string) string {
	if classifyEcosystem(ecosystem) == ecosystemPython {
		return normalizePython(name)
	}
	return strings.ToLower(name)
}

// normalizePython implements PEP 503 name normalization.
// Reference: https://packaging.python.org/en/latest/specifications/name-normalization/
// Renovate equivalent: lib/modules/datasource/pypi/common.ts → normalizePythonDepName
func normalizePython(name string) string {
	return pypiSeparators.ReplaceAllString(strings.ToLower(name), "-")
}

type ecosystemClass int

const (
	ecosystemDefault ecosystemClass = iota
	ecosystemPython
)

// classifyEcosystem maps various ecosystem identifiers (from Trivy PkgType
// properties or PURL types) to a normalization class.
func classifyEcosystem(ecosystem string) ecosystemClass {
	switch strings.ToLower(ecosystem) {
	case "pip", "pipenv", "poetry", "uv", "pylock", "python-pkg", "conda-pkg",
		"conda-environment", "pypi", "python":
		return ecosystemPython
	default:
		return ecosystemDefault
	}
}
