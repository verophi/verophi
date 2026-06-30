package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/verophi/verophi/internal/version_info"
	"github.com/verophi/verophi/pkg/model"
)

// Mode selects the output format.
type Mode int

const (
	ModeDefault Mode = iota
	ModeVerbose
	ModeCompact
	ModeJSON
	ModeQuiet
)

// Options controls rendering behavior.
type Options struct {
	Mode       Mode
	Platform   Platform
	IsTTY      bool
	NoColor    bool
	SBOMName   string // base filename of the SBOM, shown in the header
	SBOMFormat string // e.g. "CycloneDX 1.7", shown in the header
}

// Render writes the analysis result to the writer in the selected mode.
func Render(result *model.AnalysisResult, opts Options, w io.Writer) error {
	switch opts.Mode {
	case ModeJSON:
		return renderJSON(result, w)
	case ModeQuiet:
		return nil // no output
	case ModeCompact:
		if result.Correlation.Status == model.CorrelationNotRun || result.Correlation.Status == model.CorrelationFailed {
			return renderStandaloneCompact(result, w)
		}
		return renderCompact(result, opts, w)
	case ModeVerbose:
		return renderDefault(result, opts, w, true)
	default:
		return renderDefault(result, opts, w, false)
	}
}

func renderJSON(result *model.AnalysisResult, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// colorizer wraps severity text in ANSI color when enabled (TTY and not
// NO_COLOR). Color is additive only and never changes layout: callers color
// either line-trailing tokens or a single already-placed character.
type colorizer struct{ on bool }

func newColorizer(opts Options) colorizer {
	return colorizer{on: opts.IsTTY && !opts.NoColor}
}

func sevAnsi(level string) string {
	switch level {
	case "Critical":
		return "1;31" // bold red
	case "High":
		return "31" // red
	case "Medium":
		return "33" // yellow
	case "Low":
		return "36" // cyan
	}
	return ""
}

func (c colorizer) wrap(level, s string) string {
	if !c.on {
		return s
	}
	code := sevAnsi(level)
	if code == "" {
		return s
	}
	return "\033[" + code + "m" + s + "\033[0m"
}

// counts renders "C:.. H:.. M:.. L:.." with each token colored by its severity.
func (c colorizer) counts(crit, high, med, low int) string {
	return fmt.Sprintf("%s %s %s %s",
		c.wrap("Critical", fmt.Sprintf("C:%d", crit)),
		c.wrap("High", fmt.Sprintf("H:%d", high)),
		c.wrap("Medium", fmt.Sprintf("M:%d", med)),
		c.wrap("Low", fmt.Sprintf("L:%d", low)))
}

func renderDefault(result *model.AnalysisResult, opts Options, w io.Writer, verbose bool) error {
	p := opts.Platform
	if p == nil {
		p = gitlabPresenter{}
	}

	s := result.AdvisorySummary
	col := newColorizer(opts)

	// Header: verophi <ver>  <sbom> (<format>)  <platform>:<repo>
	header := fmt.Sprintf("verophi %s", version_info.Version)
	if opts.SBOMName != "" {
		if opts.SBOMFormat != "" {
			header += fmt.Sprintf("  %s (%s)", opts.SBOMName, opts.SBOMFormat)
		} else {
			header += fmt.Sprintf("  %s", opts.SBOMName)
		}
	}
	if result.Correlation.Status == model.CorrelationComplete && result.Correlation.Repository != "" {
		header += fmt.Sprintf("  %s:%s", result.Correlation.Platform, result.Correlation.Repository)
	}
	fmt.Fprintf(w, "%s\n\n", header)

	if result.Correlation.Status == model.CorrelationNotRun || result.Correlation.Status == model.CorrelationFailed {
		renderStandalone(result, opts, w, verbose)
		return nil
	}

	matched, noMatch, unparsed := countRequests(result.ChangeRequests)
	abbrev := p.Abbrev()

	// Build primary values and measure the widest to align detail columns.
	cvesVal := fmt.Sprintf("%d", s.Total)
	matchVal := fmt.Sprintf("%d/%d", s.Correlated, s.Total)
	visVal := fmt.Sprintf("%.0f", result.TotalImpactScore)
	mrsVal := fmt.Sprintf("%d", matched+noMatch+unparsed)

	valW := maxLen(cvesVal, matchVal, visVal, mrsVal)

	fmt.Fprintf(w, "%-12s%-*s  %s\n", "CVEs", valW, cvesVal, col.counts(s.Critical, s.High, s.Medium, s.Low))
	fmt.Fprintf(w, "%-12s%s\n", "CVE match", matchVal)

	if result.ReducibleImpactScore != nil {
		remaining := result.TotalImpactScore - *result.ReducibleImpactScore
		fmt.Fprintf(w, "%-12s%-*s  reducible: %.0f, remaining: %.0f\n",
			"VIS", valW, visVal, *result.ReducibleImpactScore, remaining)
	} else {
		fmt.Fprintf(w, "%-12s%s\n", "VIS", visVal)
	}

	fmt.Fprintf(w, "%-12s%-*s  matched: %d, no match: %d, unparsed: %d\n",
		abbrev+"s", valW, mrsVal, matched, noMatch, unparsed)
	fmt.Fprintf(w, "%-12s%s critical  %s high  %s medium  %s low\n\n",
		"severity", col.wrap("Critical", "C"), col.wrap("High", "H"), col.wrap("Medium", "M"), col.wrap("Low", "L"))
	fmt.Fprintf(w, "note: %s VIS can overlap; reducible VIS counts matched CVEs once.\n\n", abbrev)

	if matched > 0 {
		fmt.Fprintf(w, "MERGE FIRST  (by VIS, then VME)\n\n")
		jointMap := computeJointFixes(result)
		partialMap := computePartialFixes(result)
		rank := 1
		for _, cr := range result.ChangeRequests {
			if cr.Status != model.StatusMatched {
				continue
			}
			renderRankedEntry(w, p, col, cr, rank, verbose, jointMap[cr.Number], partialMap[cr.Number])
			rank++
		}
	}

	renderGaps(result, p, col, w, verbose, computePartialFixes(result))

	return nil
}

func renderStandalone(result *model.AnalysisResult, opts Options, w io.Writer, verbose bool) {
	s := result.AdvisorySummary
	col := newColorizer(opts)
	mode := "standalone (SBOM only)"
	if result.Correlation.Status == model.CorrelationFailed {
		mode = "standalone (platform query failed)"
	}
	cvesVal := fmt.Sprintf("%d", s.Total)
	visVal := fmt.Sprintf("%.0f", result.TotalImpactScore)
	valW := maxLen(cvesVal, visVal, mode)

	fmt.Fprintf(w, "%-12s%s\n", "mode", mode)
	fmt.Fprintf(w, "%-12s%-*s  %s\n", "CVEs", valW, cvesVal, col.counts(s.Critical, s.High, s.Medium, s.Low))
	fmt.Fprintf(w, "%-12s%s\n", "VIS", visVal)
	fmt.Fprintf(w, "%-12s%s critical  %s high  %s medium  %s low\n\n",
		"severity", col.wrap("Critical", "C"), col.wrap("High", "H"), col.wrap("Medium", "M"), col.wrap("Low", "L"))

	advs := result.UncorrelatedAdvisories
	if len(advs) > 0 {
		fmt.Fprintf(w, "CVEs  (%d)\n", len(advs))
		limit := len(advs)
		if !verbose && limit > 20 {
			limit = 20
		}
		idW, depW := standaloneColWidths(advs[:limit])
		fmt.Fprintf(w, "  %-3s  %-*s  %-*s  %s\n", "SEV", idW, "ID", depW, "DEPENDENCY", "KNOWN FIX")
		for i, adv := range advs {
			if i >= limit {
				fmt.Fprintf(w, "  +%d more (--verbose)\n", len(advs)-limit)
				break
			}
			sev := col.wrap(adv.Severity.Level, fmt.Sprintf("%-3s", severityChar(adv.Severity)))
			fmt.Fprintf(w, "  %s  %-*s  %-*s  %s\n",
				sev, idW, adv.ID, depW, standaloneDep(adv), standaloneFix(adv))
		}
	}

	fmt.Fprintf(w, "\nhint: add --gitlab-project PROJECT or --github-repo OWNER/REPO to correlate change requests\n")
}

// renderStandaloneCompact renders the SBOM-only view as a terse one-row-per-CVE
// scan list, instead of the (empty) change-request table.
func renderStandaloneCompact(result *model.AnalysisResult, w io.Writer) error {
	s := result.AdvisorySummary
	fmt.Fprintf(w, "# verophi  cves=%d C:%d H:%d M:%d L:%d  vis=%.0f  standalone\n",
		s.Total, s.Critical, s.High, s.Medium, s.Low, result.TotalImpactScore)
	advs := result.UncorrelatedAdvisories
	idW, depW := standaloneColWidths(advs)
	header := fmt.Sprintf("%-3s  %-*s  %-*s  %s", "SEV", idW, "ID", depW, "DEPENDENCY", "KNOWN-FIX")
	fmt.Fprintln(w, strings.TrimRight(header, " "))
	for _, adv := range advs {
		row := fmt.Sprintf("%-3s  %-*s  %-*s  %s",
			severityChar(adv.Severity), idW, adv.ID, depW, standaloneDep(adv), standaloneFix(adv))
		fmt.Fprintln(w, strings.TrimRight(row, " "))
	}
	return nil
}

func standaloneDep(adv model.Advisory) string {
	if len(adv.Occurrences) == 0 {
		return ""
	}
	return adv.Occurrences[0].DependencyName + "@" + adv.Occurrences[0].AffectedVersion
}

func standaloneFix(adv model.Advisory) string {
	if len(adv.Occurrences) > 0 && adv.Occurrences[0].FixVersion != "" {
		return adv.Occurrences[0].FixVersion
	}
	return "unknown"
}

// standaloneColWidths sizes the ID and DEPENDENCY columns to their widest value
// (capped) so long GHSA ids and dependency names do not break alignment.
func standaloneColWidths(advs []model.Advisory) (idW, depW int) {
	idW, depW = len("ID"), len("DEPENDENCY")
	for _, adv := range advs {
		if l := len(adv.ID); l > idW {
			idW = l
		}
		if l := len(standaloneDep(adv)); l > depW {
			depW = l
		}
	}
	if depW > 40 {
		depW = 40
	}
	return idW, depW
}

func renderRankedEntry(w io.Writer, p Platform, col colorizer, cr model.ChangeRequest, rank int, verbose bool, joints []jointFix, partials []partialFix) {
	id := p.IDLabel(cr.Number)

	title := cr.Title
	if len(cr.Assessments) == 1 {
		c := cr.Assessments[0].Change
		title = fmt.Sprintf("%s %s -> %s", c.DependencyName, c.CurrentVersion, c.TargetVersion)
	}

	vme := "n/a (unknown risk)"
	if cr.MergeEfficiency != nil {
		vme = fmt.Sprintf("%.1f", *cr.MergeEfficiency)
	}

	fmt.Fprintf(w, "  %3d  %-5s %-35s %-8s VIS %.0f  VME %s\n",
		rank, id, truncate(title, 35), cr.RiskTier.Name, cr.ImpactScore, vme)

	f := cr.Fixes
	// Drop the "fixes 0 CVEs" line entirely: VIS 0 already appears in the ranked
	// line above, and any partial contribution is explained by the needs lines.
	if f.Total > 0 {
		fmt.Fprintf(w, "%sfixes %d %s  %s\n",
			contIndent, f.Total, pluralizeCVE(f.Total), col.counts(f.Critical, f.High, f.Medium, f.Low))
	}

	for _, jf := range joints {
		labels := make([]string, len(jf.partners))
		for i, n := range jf.partners {
			labels[i] = p.IDLabel(n)
		}
		fmt.Fprintf(w, "%sneeds %s to fully fix %s\n",
			contIndent, strings.Join(labels, ", "), col.wrap(jf.severity.Level, jf.advisoryID))
	}

	if len(partials) > 0 {
		ids := make([]string, len(partials))
		for i, pf := range partials {
			ids[i] = col.wrap(pf.severity.Level, pf.advisoryID)
		}
		blockers := partialBlockerUnion(partials)
		fmt.Fprintf(w, "%spartially addresses %s (no update for %s)\n",
			contIndent, strings.Join(ids, ", "), blockers)
	}

	if len(cr.Assessments) > 1 || cr.UnparsedDeps > 0 {
		line := fmt.Sprintf("%sdeps: %d  with CVEs: %d", contIndent, len(cr.Assessments), countMatched(cr))
		if cr.UnparsedDeps > 0 {
			line += fmt.Sprintf("  (%d unparsed)", cr.UnparsedDeps)
		}
		fmt.Fprintln(w, line)
	}

	if cr.SplitCandidate != nil {
		sc := cr.SplitCandidate
		fmt.Fprintf(w, "%ssplit: %s  VIS %.0f/%.0f  risk %s  VME %.1f\n",
			contIndent, sc.DependencyName, sc.ImpactScore, cr.ImpactScore, sc.RiskTier.Name, sc.MergeEfficiency)
	}

	fmt.Fprintf(w, "%s%s\n", contIndent, cr.URL)
	if verbose {
		renderVerboseDetail(w, cr)
	}
	fmt.Fprintln(w)
}

// renderVerboseDetail adds the per-request diagnostic block (R21): status, age,
// risk tier, labels, and a per-child breakdown with Change-VIS, isolated
// efficiency, and the full advisory ids each child matches.
func renderVerboseDetail(w io.Writer, cr model.ChangeRequest) {
	labels := "-"
	if len(cr.Labels) > 0 {
		labels = strings.Join(cr.Labels, ", ")
	}
	age := fmt.Sprintf("%dd", cr.AgeDays)
	if cr.Stale {
		age += " (stale)"
	}
	fmt.Fprintf(w, "%sstatus: %s  age: %s  risk: %s  labels: %s\n",
		contIndent, cr.Status, age, cr.RiskTier.Name, labels)
	fmt.Fprintf(w, "%schanges:\n", contIndent)

	// size columns to the widest child so grouped change rows line up
	nameW, curW, tgtW, ctW, visW := 0, 0, 0, 0, 0
	for _, a := range cr.Assessments {
		c := a.Change
		if l := len(c.DependencyName); l > nameW {
			nameW = l
		}
		if l := len(c.CurrentVersion); l > curW {
			curW = l
		}
		if l := len(c.TargetVersion); l > tgtW {
			tgtW = l
		}
		if l := len(c.ChangeType.Name); l > ctW {
			ctW = l
		}
		if l := len(fmt.Sprintf("%.0f", a.ImpactScore)); l > visW {
			visW = l
		}
	}
	for _, a := range cr.Assessments {
		c := a.Change
		eff := "n/a"
		if c.ChangeType.Risk > 0 {
			eff = fmt.Sprintf("%.1f", a.ImpactScore/float64(c.ChangeType.Risk))
		}
		ids := advisoryIDs(a.AdvisoryMatches)
		row := fmt.Sprintf("%s  %-*s  %-*s -> %-*s  %-*s  VIS %*.0f  VME %-4s%s",
			contIndent, nameW, c.DependencyName, curW, c.CurrentVersion, tgtW, c.TargetVersion,
			ctW, c.ChangeType.Name, visW, a.ImpactScore, eff, ids)
		fmt.Fprintln(w, strings.TrimRight(row, " "))
	}
}

// advisoryIDs renders the sorted, deduplicated advisory ids of a child as
// "  [CVE-..., GHSA-...]", or empty when the child matched none.
func advisoryIDs(matches []model.AdvisoryMatch) string {
	if len(matches) == 0 {
		return ""
	}
	seen := make(map[string]bool, len(matches))
	var ids []string
	for _, m := range matches {
		if !seen[m.Advisory.ID] {
			seen[m.Advisory.ID] = true
			ids = append(ids, m.Advisory.ID)
		}
	}
	sort.Strings(ids)
	return "  [" + strings.Join(ids, ", ") + "]"
}

// contIndent aligns continuation lines under the title column of a ranked entry.
// Layout: 2 spaces + rank(%3d) + 2 spaces + id(%-5s) + 1 space = column 13.
const contIndent = "             "

// compactColFmt lays out the compact columns; header and rows share it so they
// always align. All args are strings (numbers pre-formatted). Trailing padding
// is trimmed per line so empty FLAGS leaves no trailing whitespace.
const compactColFmt = "%-4s  %-5s %-33s %-7s %5s %5s  %-8s %5s  %s"

func renderCompact(result *model.AnalysisResult, opts Options, w io.Writer) error {
	p := opts.Platform
	if p == nil {
		p = gitlabPresenter{}
	}
	abbr := p.Abbrev()
	tok := strings.ToLower(abbr) // "mr" / "pr"

	s := result.AdvisorySummary
	matched, noMatch, unparsed := countRequests(result.ChangeRequests)
	fmt.Fprintf(w, "# verophi  cves=%d C:%d H:%d M:%d L:%d  vis=%.0f",
		s.Total, s.Critical, s.High, s.Medium, s.Low, result.TotalImpactScore)
	if result.ReducibleImpactScore != nil {
		fmt.Fprintf(w, " reducible=%.0f remaining=%.0f",
			*result.ReducibleImpactScore, result.TotalImpactScore-*result.ReducibleImpactScore)
	}
	fmt.Fprintf(w, "  matched_%ss=%d no_match_%ss=%d unparsed_%ss=%d\n", tok, matched, tok, noMatch, tok, unparsed)

	header := fmt.Sprintf(compactColFmt, "RANK", abbr, "DEP / GROUP", "RISK", "VIS", "VME", "CVE-DEPS", "AGE_D", "FLAGS")
	fmt.Fprintln(w, strings.TrimRight(header, " "))

	jointMap := computeJointFixes(result)
	partialMap := computePartialFixes(result)
	rank := 1
	for _, cr := range result.ChangeRequests {
		if cr.Status != model.StatusMatched {
			continue
		}
		id := p.IDLabel(cr.Number)
		title := cr.Title
		if len(cr.Assessments) == 1 {
			title = cr.Assessments[0].Change.DependencyName
		}
		vme := "n/a"
		if cr.MergeEfficiency != nil {
			vme = fmt.Sprintf("%.1f", *cr.MergeEfficiency)
		}
		cveDeps := fmt.Sprintf("%d/%d", countMatched(cr), len(cr.Assessments))
		row := fmt.Sprintf(compactColFmt,
			strconv.Itoa(rank), id, truncate(title, 33), cr.RiskTier.Name,
			fmt.Sprintf("%.0f", cr.ImpactScore), vme, cveDeps,
			strconv.Itoa(cr.AgeDays), buildFlags(cr, p, jointPartnerUnion(jointMap[cr.Number]), partialMap[cr.Number]))
		fmt.Fprintln(w, strings.TrimRight(row, " "))
		rank++
	}
	return nil
}

func renderGaps(result *model.AnalysisResult, p Platform, col colorizer, w io.Writer, verbose bool, partialMap map[int][]partialFix) {
	abbr := p.Abbrev()

	advPartialCRs := map[string][]int{}
	for crNum, pfs := range partialMap {
		for _, pf := range pfs {
			advPartialCRs[pf.advisoryID] = appendUniqueInt(advPartialCRs[pf.advisoryID], crNum)
		}
	}
	for k := range advPartialCRs {
		sort.Ints(advPartialCRs[k])
	}

	if len(result.UncorrelatedAdvisories) > 0 {
		advs := result.UncorrelatedAdvisories
		fmt.Fprintf(w, "CVEs WITHOUT A MATCHED %s  (%d)\n", abbr, len(advs))
		limit := gapLimit(len(advs), verbose)
		idW, depW := len("ID"), len("DEPENDENCY")
		for i := 0; i < limit; i++ {
			if l := len(advs[i].ID); l > idW {
				idW = l
			}
			if l := len(standaloneDep(advs[i])); l > depW {
				depW = l
			}
		}
		if verbose {
			h := fmt.Sprintf("  %-3s  %-*s  %-*s  %-10s  %s", "SEV", idW, "ID", depW, "DEPENDENCY", "KNOWN-FIX", "NOTE")
			fmt.Fprintln(w, strings.TrimRight(h, " "))
		} else {
			h := fmt.Sprintf("  %-3s  %-*s  %-*s  %s", "SEV", idW, "ID", depW, "DEPENDENCY", "NOTE")
			fmt.Fprintln(w, strings.TrimRight(h, " "))
		}
		for i, adv := range advs {
			if i >= limit {
				fmt.Fprintf(w, "  +%d more (--verbose)\n", len(advs)-limit)
				break
			}
			sev := col.wrap(adv.Severity.Level, fmt.Sprintf("%-3s", severityChar(adv.Severity)))
			note := ""
			if adv.AddressedOccurrences > 0 && adv.AddressedOccurrences < len(adv.Occurrences) {
				crLabels := make([]string, 0, len(advPartialCRs[adv.ID]))
				for _, n := range advPartialCRs[adv.ID] {
					crLabels = append(crLabels, p.IDLabel(n))
				}
				if len(crLabels) > 0 {
					note = fmt.Sprintf("partially addressed in %s (%d/%d components)",
						strings.Join(crLabels, ", "), adv.AddressedOccurrences, len(adv.Occurrences))
				} else {
					note = fmt.Sprintf("partially addressed (%d/%d components)", adv.AddressedOccurrences, len(adv.Occurrences))
				}
			}
			var line string
			dep := standaloneDep(adv)
			if adv.AddressedOccurrences > 0 && adv.AddressedOccurrences < len(adv.Occurrences) {
				for _, occ := range adv.Occurrences {
					if !occ.Addressed {
						dep = occ.DependencyName + "@" + occ.AffectedVersion
						break
					}
				}
			}
			if verbose {
				line = fmt.Sprintf("  %s  %-*s  %-*s  %-10s  %s",
					sev, idW, adv.ID, depW, dep, standaloneFix(adv), note)
			} else {
				line = fmt.Sprintf("  %s  %-*s  %-*s  %s",
					sev, idW, adv.ID, depW, dep, note)
			}
			fmt.Fprintln(w, strings.TrimRight(line, " "))
		}
		fmt.Fprintln(w)
	}

	var unmatched, unparsedList []model.ChangeRequest
	for _, cr := range result.ChangeRequests {
		switch cr.Status {
		case model.StatusUnmatched:
			unmatched = append(unmatched, cr)
		case model.StatusUnparsed:
			unparsedList = append(unparsedList, cr)
		}
	}

	if len(unmatched) > 0 {
		fmt.Fprintf(w, "%ss WITHOUT A MATCHED CVE  (%d)\n", abbr, len(unmatched))
		idW := maxIDLabelLen(p, unmatched)
		if idW < len(abbr) {
			idW = len(abbr)
		}
		limit := gapLimit(len(unmatched), verbose)
		fmt.Fprintf(w, "  %-*s  %-45s  %s\n", idW, abbr, "DESCRIPTION", "RISK")
		for i, cr := range unmatched {
			if i >= limit {
				fmt.Fprintf(w, "  +%d more (--verbose)\n", len(unmatched)-limit)
				break
			}
			id := p.IDLabel(cr.Number)
			desc := cr.Title
			if len(cr.Assessments) == 1 {
				c := cr.Assessments[0].Change
				desc = fmt.Sprintf("%s %s -> %s", c.DependencyName, c.CurrentVersion, c.TargetVersion)
			}
			fmt.Fprintf(w, "  %-*s  %-45s  %s\n", idW, id, truncate(desc, 45), cr.RiskTier.Name)
		}
		fmt.Fprintln(w)
	}

	if len(unparsedList) > 0 {
		fmt.Fprintf(w, "%ss WITH NO CHANGES PARSED  (%d)\n", abbr, len(unparsedList))
		idW := maxIDLabelLen(p, unparsedList)
		if idW < len(abbr) {
			idW = len(abbr)
		}
		limit := gapLimit(len(unparsedList), verbose)
		fmt.Fprintf(w, "  %-*s  %s\n", idW, abbr, "TITLE")
		for i, cr := range unparsedList {
			if i >= limit {
				fmt.Fprintf(w, "  +%d more (--verbose)\n", len(unparsedList)-limit)
				break
			}
			id := p.IDLabel(cr.Number)
			title := cr.Title
			if title == "" {
				title = "(no title)"
			}
			fmt.Fprintf(w, "  %-*s  %s\n", idW, id, title)
		}
		fmt.Fprintln(w)
	}
}

// gapLimit returns how many gap entries to show: all when verbose, else at most 5.
func gapLimit(n int, verbose bool) int {
	if verbose || n <= 5 {
		return n
	}
	return 5
}

// maxIDLabelLen returns the widest platform id label in the slice.
func maxIDLabelLen(p Platform, requests []model.ChangeRequest) int {
	w := 0
	for _, cr := range requests {
		if l := len(p.IDLabel(cr.Number)); l > w {
			w = l
		}
	}
	return w
}

// Helpers

func countRequests(requests []model.ChangeRequest) (matched, noMatch, unparsed int) {
	for _, cr := range requests {
		switch cr.Status {
		case model.StatusMatched:
			matched++
		case model.StatusUnmatched:
			noMatch++
		case model.StatusUnparsed:
			unparsed++
		}
	}
	return
}

func countMatched(cr model.ChangeRequest) int {
	count := 0
	for _, a := range cr.Assessments {
		if len(a.AdvisoryMatches) > 0 {
			count++
		}
	}
	return count
}

func severityChar(s model.Severity) string {
	switch s.Level {
	case "Critical":
		return "C"
	case "High":
		return "H"
	case "Medium":
		return "M"
	case "Low":
		return "L"
	default:
		return "?"
	}
}

func truncate(s string, maxWidth int) string {
	if len(s) <= maxWidth {
		return s
	}
	return s[:maxWidth-3] + "..."
}

// maxLen returns the length of the longest string in the list.
func maxLen(ss ...string) int {
	w := 0
	for _, s := range ss {
		if len(s) > w {
			w = len(s)
		}
	}
	return w
}

// pluralizeCVE returns "CVE" for exactly one and "CVEs" otherwise.
func pluralizeCVE(n int) string {
	if n == 1 {
		return "CVE"
	}
	return "CVEs"
}

func buildFlags(cr model.ChangeRequest, p Platform, jointPartners []int, partials []partialFix) string {
	var flags []string
	if cr.Stale {
		flags = append(flags, "stale")
	}
	if cr.HasUnknownRisk {
		flags = append(flags, "unknown")
	}
	if cr.SplitCandidate != nil {
		flags = append(flags, "split")
	}
	if len(cr.Assessments) > 1 {
		flags = append(flags, fmt.Sprintf("grouped:%d", len(cr.Assessments)))
	}
	if len(jointPartners) > 0 {
		labels := make([]string, len(jointPartners))
		for i, n := range jointPartners {
			labels[i] = p.IDLabel(n)
		}
		flags = append(flags, "needs:"+strings.Join(labels, "+"))
	}
	if len(partials) > 0 {
		flags = append(flags, fmt.Sprintf("partial:%d", len(partials)))
	}
	result := ""
	for i, f := range flags {
		if i > 0 {
			result += ","
		}
		result += f
	}
	return result
}
