package logging

import (
	"log/slog"
	"os"
	"strings"
)

func Setup(level string) {
	if level == "" {
		level = os.Getenv("VEROPHI_LOG_LEVEL")
	}
	if level == "" {
		level = "info"
	}

	var slogLevel slog.Level
	switch strings.ToLower(level) {
	case "debug":
		slogLevel = slog.LevelDebug
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slogLevel,
	})
	slog.SetDefault(slog.New(handler))
}
