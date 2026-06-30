package logging

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetup_DefaultLevel(t *testing.T) {
	t.Setenv("VEROPHI_LOG_LEVEL", "")
	Setup("")
	ctx := context.Background()
	assert.True(t, slog.Default().Enabled(ctx, slog.LevelInfo))
	assert.False(t, slog.Default().Enabled(ctx, slog.LevelDebug))
}

func TestSetup_DebugLevel(t *testing.T) {
	Setup("debug")
	assert.True(t, slog.Default().Enabled(context.Background(), slog.LevelDebug))
}

func TestSetup_WarnLevel(t *testing.T) {
	Setup("warn")
	ctx := context.Background()
	assert.False(t, slog.Default().Enabled(ctx, slog.LevelInfo))
	assert.True(t, slog.Default().Enabled(ctx, slog.LevelWarn))
}

func TestSetup_ErrorLevel(t *testing.T) {
	Setup("error")
	ctx := context.Background()
	assert.False(t, slog.Default().Enabled(ctx, slog.LevelWarn))
	assert.True(t, slog.Default().Enabled(ctx, slog.LevelError))
}

func TestSetup_CaseInsensitive(t *testing.T) {
	ctx := context.Background()

	Setup("DEBUG")
	assert.True(t, slog.Default().Enabled(ctx, slog.LevelDebug))

	Setup("Info")
	assert.True(t, slog.Default().Enabled(ctx, slog.LevelInfo))
	assert.False(t, slog.Default().Enabled(ctx, slog.LevelDebug))
}

func TestSetup_FromEnvVar(t *testing.T) {
	os.Setenv("VEROPHI_LOG_LEVEL", "debug")
	defer os.Unsetenv("VEROPHI_LOG_LEVEL")

	Setup("")
	assert.True(t, slog.Default().Enabled(context.Background(), slog.LevelDebug))
}

func TestSetup_ExplicitOverridesEnv(t *testing.T) {
	os.Setenv("VEROPHI_LOG_LEVEL", "debug")
	defer os.Unsetenv("VEROPHI_LOG_LEVEL")

	ctx := context.Background()
	Setup("error")
	assert.False(t, slog.Default().Enabled(ctx, slog.LevelDebug))
	assert.True(t, slog.Default().Enabled(ctx, slog.LevelError))
}
