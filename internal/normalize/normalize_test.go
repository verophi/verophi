package normalize

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDependencyName_Python(t *testing.T) {
	// PEP 503: case-insensitive, runs of [-_.] collapse to single hyphen.
	tests := []struct {
		name      string
		input     string
		ecosystem string
		want      string
	}{
		{"lowercase already", "requests", "pip", "requests"},
		{"mixed case", "PyYAML", "pip", "pyyaml"},
		{"underscore to hyphen", "my_package", "pip", "my-package"},
		{"dot to hyphen", "zope.interface", "pip", "zope-interface"},
		{"mixed separators", "Friendly-._.-Bard", "pip", "friendly-bard"},
		{"multiple underscores", "some__pkg", "pip", "some-pkg"},
		{"multiple hyphens", "some--pkg", "pip", "some-pkg"},
		{"dot underscore mix", "a.b_c-d", "pip", "a-b-c-d"},
		{"all caps", "PILLOW", "pip", "pillow"},
		{"pipenv ecosystem", "PyYAML", "pipenv", "pyyaml"},
		{"poetry ecosystem", "PyYAML", "poetry", "pyyaml"},
		{"uv ecosystem", "PyYAML", "uv", "pyyaml"},
		{"pypi ecosystem", "PyYAML", "pypi", "pyyaml"},
		{"python-pkg ecosystem", "PyYAML", "python-pkg", "pyyaml"},
		{"conda-pkg ecosystem", "PyYAML", "conda-pkg", "pyyaml"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, DependencyName(tt.input, tt.ecosystem))
		})
	}
}

func TestDependencyName_NonPython(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		ecosystem string
		want      string
	}{
		{"npm lowercase", "lodash", "npm", "lodash"},
		{"npm scoped", "@types/node", "npm", "@types/node"},
		{"go module", "golang.org/x/crypto", "gomod", "golang.org/x/crypto"},
		{"nuget preserves dots", "Newtonsoft.Json", "nuget", "newtonsoft.json"},
		{"cargo", "serde", "cargo", "serde"},
		{"bundler", "rails", "bundler", "rails"},
		{"composer", "pear/log", "composer", "pear/log"},
		{"hex", "phoenix", "hex", "phoenix"},
		{"pub", "http", "pub", "http"},
		{"empty ecosystem", "lodash", "", "lodash"},
		{"unknown ecosystem", "foo", "unknown", "foo"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, DependencyName(tt.input, tt.ecosystem))
		})
	}
}

func TestDependencyName_Maven(t *testing.T) {
	// Maven is NOT collapsed to the artifactId here (that would cross-match
	// different groupIds, R14.1). Maven identity is handled by PURL in the
	// analysis; this fallback only lowercases the full coordinate.
	tests := []struct {
		name      string
		input     string
		ecosystem string
		want      string
	}{
		{"full coordinate preserved", "org.apache.logging.log4j:log4j-core", "maven", "org.apache.logging.log4j:log4j-core"},
		{"bare artifactId unchanged", "log4j-core", "maven", "log4j-core"},
		{"different groupId stays distinct", "com.example:log4j-core", "maven", "com.example:log4j-core"},
		{"gradle lowercased", "org.springframework:Spring-Core", "gradle", "org.springframework:spring-core"},
		{"mixed case", "com.Google:Guava", "maven", "com.google:guava"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, DependencyName(tt.input, tt.ecosystem))
		})
	}
}

func TestDependencyName_PythonMatchesRenovate(t *testing.T) {
	// Verify that our normalization produces the same result as Renovate's
	// normalizePythonDepName: name.replace(/[-_.]+/g, '-').toLowerCase()
	pairs := []struct {
		trivyName    string
		renovateName string
	}{
		{"PyYAML", "pyyaml"},
		{"Pillow", "pillow"},
		{"requests", "requests"},
		{"google-cloud-storage", "google-cloud-storage"},
		{"python_dateutil", "python-dateutil"},
		{"zope.interface", "zope-interface"},
		{"Jinja2", "jinja2"},
		{"MarkupSafe", "markupsafe"},
		{"typing_extensions", "typing-extensions"},
		{"importlib_metadata", "importlib-metadata"},
	}

	for _, tt := range pairs {
		t.Run(tt.trivyName, func(t *testing.T) {
			normalized := DependencyName(tt.trivyName, "pip")
			assert.Equal(t, tt.renovateName, normalized,
				"Trivy name %q should normalize to Renovate name %q", tt.trivyName, tt.renovateName)
		})
	}
}

func TestClassifyEcosystem(t *testing.T) {
	pythonEcosystems := []string{
		"pip", "pipenv", "poetry", "uv", "pylock",
		"python-pkg", "conda-pkg", "conda-environment", "pypi", "python",
	}
	for _, eco := range pythonEcosystems {
		assert.Equal(t, ecosystemPython, classifyEcosystem(eco), "ecosystem %q should be Python", eco)
	}

	mavenEcosystems := []string{"maven", "gradle"}
	for _, eco := range mavenEcosystems {
		assert.Equal(t, ecosystemDefault, classifyEcosystem(eco), "maven is no longer special-cased; identity is via PURL")
	}

	defaultEcosystems := []string{
		"npm", "gomod", "nuget", "cargo", "bundler",
		"composer", "hex", "pub", "cocoapods", "swift", "",
	}
	for _, eco := range defaultEcosystems {
		assert.Equal(t, ecosystemDefault, classifyEcosystem(eco), "ecosystem %q should be default", eco)
	}
}

func TestDependencyName_EmptyString(t *testing.T) {
	assert.Equal(t, "", DependencyName("", "npm"))
	assert.Equal(t, "", DependencyName("", "pip"))
	assert.Equal(t, "", DependencyName("", "maven"))
	assert.Equal(t, "", DependencyName("", ""))
}
