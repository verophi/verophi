package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/verophi/verophi/internal/analysis"
	"github.com/verophi/verophi/internal/change"
	"github.com/verophi/verophi/internal/logging"
	"github.com/verophi/verophi/internal/output"
	"github.com/verophi/verophi/internal/platform"
	"github.com/verophi/verophi/internal/sbom"
	"github.com/verophi/verophi/internal/updater"
	"github.com/verophi/verophi/internal/version_info"
	"github.com/verophi/verophi/pkg/model"
)

func main() {
	rootCmd := &cobra.Command{
		Use:           "verophi",
		Short:         "Correlate CVEs with open Renovate updates",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	rootCmd.AddCommand(newAnalyzeCmd())
	rootCmd.AddCommand(newVersionCmd())

	if err := rootCmd.Execute(); err != nil {
		if _, ok := err.(*thresholdExceededError); ok {
			fmt.Fprintf(os.Stderr, "\nerror: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
}

func newAnalyzeCmd() *cobra.Command {
	var (
		sbomPath, gitlabToken, gitlabURL, projectID   string
		githubToken, githubRepo, format, logLevel     string
		changeRequestLabel, changeRequestBranchPrefix string
		maxCritical, maxHigh, apiTimeout              int
		maxSBOMSize, maxRequests, staleDays           int
		noColor                                       bool
		verbose                                       bool
	)

	cmd := &cobra.Command{
		Use:   "analyze",
		Short: "Analyze an SBOM and rank open Renovate updates by security impact",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Quiet mode: raise log level
			if format == "quiet" {
				logging.Setup("error")
			} else {
				logging.Setup(logLevel)
			}

			if sbomPath == "" {
				return fmt.Errorf("--sbom flag is required")
			}

			if err := validateFormat(format); err != nil {
				return err
			}

			if gitlabToken == "" {
				gitlabToken = os.Getenv("VEROPHI_GITLAB_TOKEN")
			}
			if githubToken == "" {
				githubToken = os.Getenv("VEROPHI_GITHUB_TOKEN")
			}

			gitlabConfigured := projectID != ""
			githubConfigured := githubRepo != ""
			if gitlabConfigured && githubConfigured {
				return fmt.Errorf("cannot use both --gitlab-project and --github-repo")
			}

			sbomResult, err := sbom.ParseCycloneDX(sbomPath, int64(maxSBOMSize)*1024*1024)
			if err != nil {
				return err
			}

			// Determine correlation state and read platform
			now := time.Now()
			corr := model.Correlation{Status: model.CorrelationNotRun}
			var correlationErr error
			var rawRequests []platform.ChangeRequestRaw
			var platformTag string

			if gitlabConfigured || githubConfigured {
				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(apiTimeout)*time.Second)
				defer cancel()

				opts := platform.ReadOptions{
					Filter: platform.ChangeRequestFilter{Label: changeRequestLabel, BranchPrefix: changeRequestBranchPrefix},
					Limits: platform.FetchLimits{MaxRequests: maxRequests},
				}

				var readResult platform.ReadResult
				var readErr error

				if gitlabConfigured {
					platformTag = "gitlab"
					opts.PlatformTag = platformTag
					opts.Token = gitlabToken
					opts.BaseURL = gitlabURL
					opts.Repository = projectID

					readResult, readErr = platform.ReadGitlabMRs(ctx, opts)
				} else {
					platformTag = "github"
					opts.PlatformTag = platformTag
					opts.Token = githubToken
					opts.Repository = githubRepo

					readResult, readErr = platform.ReadGithubPRs(ctx, opts)
				}

				corr.Platform = platformTag
				corr.Repository = opts.Repository

				if readErr != nil {
					slog.Error("platform query failed, falling back to SBOM-only", "error", readErr)
					corr.Status = model.CorrelationFailed
					correlationErr = readErr
				} else {
					corr.Status = model.CorrelationComplete
					rawRequests = readResult.Requests
					if readResult.Truncated {
						slog.Warn("update list truncated", "limit", maxRequests)
					}
				}
			}

			requests := change.Build(rawRequests, updater.RenovateParser{})

			result := analysis.Analyze(sbomResult, requests, corr, analysis.Options{Now: now, StaleDays: staleDays})

			mode := selectMode(resolveFormat(format, verbose, cmd.Flags().Changed("format")))
			opts := output.Options{
				Mode:       mode,
				Platform:   output.ForPlatform(platformTag),
				IsTTY:      isTTY(os.Stdout),
				NoColor:    noColor || os.Getenv("NO_COLOR") != "",
				SBOMName:   filepath.Base(sbomPath),
				SBOMFormat: sbomSourceFormat(sbomResult),
			}
			if err := output.Render(result, opts, os.Stdout); err != nil {
				return fmt.Errorf("render: %w", err)
			}

			if corr.Status == model.CorrelationFailed {
				return fmt.Errorf("correlation failed: %w", correlationErr)
			}

			return checkThresholds(result, maxCritical, maxHigh)
		},
	}

	cmd.Flags().StringVar(&sbomPath, "sbom", envOrDefault("VEROPHI_SBOM_PATH", ""), "Path to CycloneDX SBOM JSON")
	cmd.Flags().StringVar(&gitlabToken, "gitlab-token", "", "GitLab API token")
	cmd.Flags().StringVar(&gitlabURL, "gitlab-url", envOrDefault("VEROPHI_GITLAB_URL", "https://gitlab.com"), "GitLab instance URL")
	cmd.Flags().StringVar(&projectID, "gitlab-project", envOrDefault("VEROPHI_GITLAB_PROJECT", ""), "GitLab project")
	cmd.Flags().StringVar(&githubToken, "github-token", "", "GitHub API token")
	cmd.Flags().StringVar(&githubRepo, "github-repo", envOrDefault("VEROPHI_GITHUB_REPO", ""), "GitHub repo (owner/repo)")
	cmd.Flags().StringVar(&format, "format", envOrDefault("VEROPHI_FORMAT", "default"), "Output: default, verbose, compact, json, quiet")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "Shortcut for --format verbose (ignored when --format is set)")
	cmd.Flags().IntVar(&maxCritical, "max-critical", envOrDefaultInt("VEROPHI_MAX_CRITICAL", -1), "Max critical CVEs (-1=unlimited)")
	cmd.Flags().IntVar(&maxHigh, "max-high", envOrDefaultInt("VEROPHI_MAX_HIGH", -1), "Max high CVEs (-1=unlimited)")
	cmd.Flags().StringVar(&logLevel, "log-level", envOrDefault("VEROPHI_LOG_LEVEL", "info"), "Log level")
	cmd.Flags().StringVar(&changeRequestLabel, "renovate-label", envOrDefault("VEROPHI_RENOVATE_LABEL", "renovate"), "Label to identify Renovate updates")
	cmd.Flags().StringVar(&changeRequestBranchPrefix, "renovate-branch-prefix", envOrDefault("VEROPHI_RENOVATE_BRANCH_PREFIX", "renovate/"), "Branch prefix to identify Renovate updates")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Disable color")
	cmd.Flags().IntVar(&apiTimeout, "api-timeout", envOrDefaultInt("VEROPHI_API_TIMEOUT", 60), "API timeout (seconds)")
	cmd.Flags().IntVar(&maxSBOMSize, "max-sbom-size", envOrDefaultInt("VEROPHI_MAX_SBOM_SIZE", 100), "Max SBOM size (MB)")
	cmd.Flags().IntVar(&maxRequests, "max-requests", envOrDefaultInt("VEROPHI_MAX_REQUESTS", 1000), "Max requests to fetch")
	cmd.Flags().IntVar(&staleDays, "stale-days", envOrDefaultInt("VEROPHI_STALE_DAYS", 14), "Age in days above which an update is marked stale (0 disables)")

	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("verophi %s\n", version_info.Version)
			fmt.Printf("  commit:  %s\n", version_info.Commit)
			fmt.Printf("  built:   %s\n", version_info.BuildDate)
		},
	}
}

// validateFormat rejects an unknown --format value so a typo fails loudly
// (exit 2) instead of silently falling back to the default human output.
func validateFormat(format string) error {
	switch format {
	case "default", "verbose", "compact", "json", "quiet":
		return nil
	default:
		return fmt.Errorf("invalid --format %q: must be one of default, verbose, compact, json, quiet", format)
	}
}

// resolveFormat upgrades the default format to verbose when --verbose is set
// and --format was not explicitly provided. An explicit --format always wins.
func resolveFormat(format string, verbose, formatChanged bool) string {
	if verbose && !formatChanged {
		return "verbose"
	}
	return format
}

// sbomSourceFormat renders the SBOM format+version for the header, e.g.
// "CycloneDX 1.7". Empty when the parser supplied no format.
func sbomSourceFormat(r *model.SBOMResult) string {
	if r == nil || r.Format == "" {
		return ""
	}
	if r.SpecVersion == "" {
		return r.Format
	}
	return r.Format + " " + r.SpecVersion
}

func selectMode(format string) output.Mode {
	switch strings.ToLower(format) {
	case "json":
		return output.ModeJSON
	case "quiet":
		return output.ModeQuiet
	case "compact":
		return output.ModeCompact
	case "verbose":
		return output.ModeVerbose
	default:
		return output.ModeDefault
	}
}

type thresholdExceededError struct{ message string }

func (e *thresholdExceededError) Error() string { return e.message }

func checkThresholds(result *model.AnalysisResult, maxCritical, maxHigh int) error {
	if maxCritical >= 0 && result.AdvisorySummary.Critical > maxCritical {
		return &thresholdExceededError{fmt.Sprintf("critical CVEs (%d) exceed threshold (%d)", result.AdvisorySummary.Critical, maxCritical)}
	}
	if maxHigh >= 0 && result.AdvisorySummary.High > maxHigh {
		return &thresholdExceededError{fmt.Sprintf("high CVEs (%d) exceed threshold (%d)", result.AdvisorySummary.High, maxHigh)}
	}
	return nil
}

func isTTY(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func envOrDefault(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

func envOrDefaultInt(key string, fallback int) int {
	v, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	var i int
	if _, err := fmt.Sscanf(v, "%d", &i); err != nil {
		return fallback
	}
	return i
}
