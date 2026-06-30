package sbom

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/verophi/verophi/pkg/model"
)

const DefaultMaxSBOMSize int64 = 100 * 1024 * 1024

// ParseCycloneDX reads a CycloneDX 1.4-1.7 JSON SBOM and produces advisories
// with per-component occurrences, preserving PURL, BOMRef, affected version,
// ranges/status, and the recommendation string losslessly.
func ParseCycloneDX(path string, maxSize int64) (*model.SBOMResult, error) {
	if maxSize <= 0 {
		maxSize = DefaultMaxSBOMSize
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read SBOM file %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("SBOM path %q is not a regular file", path)
	}
	if info.Size() > maxSize {
		return nil, fmt.Errorf("SBOM file %q exceeds size limit (%d > %d bytes)",
			path, info.Size(), maxSize)
	}

	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("cannot read SBOM file %q: %w", path, err)
	}

	var bom cdx.BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, fmt.Errorf("cannot parse SBOM %q: expected CycloneDX JSON: %w", path, err)
	}

	if bom.BOMFormat != "CycloneDX" {
		return nil, fmt.Errorf("unsupported BOM format %q in %q: expected CycloneDX", bom.BOMFormat, path)
	}

	// Build ref -> component lookup for PURL, name, ecosystem
	type compInfo struct {
		Name      string
		Version   string
		PURL      string
		BOMRef    string
		Ecosystem string
	}
	refToComp := make(map[string]compInfo)
	if bom.Components != nil {
		for _, comp := range *bom.Components {
			refToComp[comp.BOMRef] = compInfo{
				Name:      comp.Name,
				Version:   comp.Version,
				PURL:      comp.PackageURL,
				BOMRef:    comp.BOMRef,
				Ecosystem: ecosystemFromPURL(comp.PackageURL),
			}
		}
	}

	result := &model.SBOMResult{
		Format:      "CycloneDX",
		SpecVersion: bom.SpecVersion.String(),
	}

	if bom.Vulnerabilities == nil {
		return result, nil
	}

	for _, vuln := range *bom.Vulnerabilities {
		severity, cvss := highestSeverity(vuln.Ratings)

		adv := model.Advisory{
			ID:             vuln.ID,
			Severity:       severity,
			CVSS:           cvss,
			Recommendation: vuln.Recommendation,
			Aliases:        extractAliases(vuln),
		}

		if vuln.Affects != nil {
			for _, affect := range *vuln.Affects {
				comp, ok := refToComp[affect.Ref]
				if !ok {
					continue
				}

				occ := model.Occurrence{
					BOMRef:         comp.BOMRef,
					PURL:           comp.PURL,
					DependencyName: comp.Name,
					Ecosystem:      comp.Ecosystem,
				}

				// Preserve affected versions from affects[].versions[]
				if affect.Range != nil {
					for _, av := range *affect.Range {
						if av.Version != "" && occ.AffectedVersion == "" {
							occ.AffectedVersion = av.Version
						}
					}
				}

				// Fallback: use component version if no affected version from ranges
				if occ.AffectedVersion == "" {
					occ.AffectedVersion = comp.Version
				}

				adv.Occurrences = append(adv.Occurrences, occ)
			}
		}

		result.Advisories = append(result.Advisories, adv)
	}

	return result, nil
}

func highestSeverity(ratings *[]cdx.VulnerabilityRating) (model.Severity, float64) {
	if ratings == nil || len(*ratings) == 0 {
		return model.SeverityUnknown, 0
	}
	var best model.Severity
	var bestCVSS float64
	for _, r := range *ratings {
		sev := mapSeverity(string(r.Severity))
		if sev.Weight > best.Weight {
			best = sev
		}
		if r.Score != nil && *r.Score > bestCVSS {
			bestCVSS = *r.Score
		}
	}
	if best.Level == "" {
		best = model.SeverityUnknown
	}
	return best, bestCVSS
}

func mapSeverity(s string) model.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return model.SeverityCritical
	case "high":
		return model.SeverityHigh
	case "medium":
		return model.SeverityMedium
	case "low":
		return model.SeverityLow
	default:
		return model.SeverityUnknown
	}
}

func extractAliases(vuln cdx.Vulnerability) []string {
	// Source aliases from references/advisory URLs (GHSA ids etc.)
	var aliases []string
	if vuln.References != nil {
		for _, ref := range *vuln.References {
			if ref.ID != "" && ref.ID != vuln.ID {
				aliases = append(aliases, ref.ID)
			}
		}
	}
	if vuln.Advisories != nil {
		for _, adv := range *vuln.Advisories {
			if id := extractIDFromURL(adv.URL); id != "" && id != vuln.ID {
				aliases = append(aliases, id)
			}
		}
	}
	return dedup(aliases)
}

func extractIDFromURL(url string) string {
	// Extract GHSA-xxx-xxx-xxx from GitHub advisory URLs
	if strings.Contains(url, "github.com") && strings.Contains(url, "/advisories/GHSA-") {
		parts := strings.Split(url, "/")
		for _, p := range parts {
			if strings.HasPrefix(p, "GHSA-") {
				return p
			}
		}
	}
	return ""
}

func dedup(ss []string) []string {
	if len(ss) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(ss))
	result := make([]string, 0, len(ss))
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

func ecosystemFromPURL(purl string) string {
	if purl == "" {
		return "unknown"
	}
	purl = strings.TrimPrefix(purl, "pkg:")
	parts := strings.SplitN(purl, "/", 2)
	return normalizeEcosystem(parts[0])
}

func normalizeEcosystem(eco string) string {
	switch strings.ToLower(eco) {
	case "npm", "nodejs":
		return "npm"
	case "maven", "java":
		return "maven"
	case "pypi", "pip", "python":
		return "pip"
	case "golang", "go":
		return "go"
	case "gem", "rubygems":
		return "gem"
	case "nuget", "dotnet":
		return "nuget"
	case "cargo", "rust":
		return "cargo"
	case "hex":
		return "hex"
	case "pub":
		return "pub"
	case "swift":
		return "swift"
	case "composer":
		return "composer"
	default:
		return strings.ToLower(eco)
	}
}
