package model

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Severity represents a vulnerability severity level with an ordinal weight.
// It marshals as its lowercase level string and unmarshals back reconstructing
// the weight from a canonical lookup.
type Severity struct {
	Level  string `json:"-"`
	Weight int    `json:"-"`
}

var (
	SeverityCritical = Severity{Level: "Critical", Weight: 8}
	SeverityHigh     = Severity{Level: "High", Weight: 4}
	SeverityMedium   = Severity{Level: "Medium", Weight: 2}
	SeverityLow      = Severity{Level: "Low", Weight: 1}
	SeverityUnknown  = Severity{Level: "Unknown", Weight: 0}
)

var severityByLevel = map[string]Severity{
	"critical": SeverityCritical,
	"high":     SeverityHigh,
	"medium":   SeverityMedium,
	"low":      SeverityLow,
	"unknown":  SeverityUnknown,
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(strings.ToLower(s.Level))
}

func (s *Severity) UnmarshalJSON(data []byte) error {
	var level string
	if err := json.Unmarshal(data, &level); err != nil {
		return err
	}
	sev, ok := severityByLevel[strings.ToLower(level)]
	if !ok {
		return fmt.Errorf("unknown severity level: %q", level)
	}
	*s = sev
	return nil
}
