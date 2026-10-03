// Package config loads, validates and resolves the pathwatch YAML configuration.
package config

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Duration is a time.Duration that parses Go syntax plus a "d" (days) suffix.
type Duration time.Duration

var dayRe = regexp.MustCompile(`(\d+(?:\.\d+)?)d`)

// ParseDuration parses Go duration syntax with an additional "d" suffix
// meaning 24 hours ("7d", "1d12h", "0.5d").
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	conv := dayRe.ReplaceAllStringFunc(s, func(m string) string {
		f, err := strconv.ParseFloat(strings.TrimSuffix(m, "d"), 64)
		if err != nil {
			return m
		}
		return strconv.FormatFloat(f*24, 'f', -1, 64) + "h"
	})
	d, err := time.ParseDuration(conv)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q (use e.g. 90s, 5m, 168h, 7d)", s)
	}
	return d, nil
}

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: duration must be a string such as \"30s\"", n.Line)
	}
	if n.Value == "0" {
		*d = 0
		return nil
	}
	v, err := ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*d = Duration(v)
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

// MarshalJSON encodes the duration as whole milliseconds (the API's unit for durations).
func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatInt(time.Duration(d).Milliseconds(), 10)), nil
}

// UnmarshalJSON accepts milliseconds (a number) or a duration string such as "30s" or "7d".
// null leaves the value unchanged.
func (d *Duration) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "null" {
		return nil
	}
	if strings.HasPrefix(s, `"`) {
		uq, err := strconv.Unquote(s)
		if err != nil {
			return fmt.Errorf("invalid duration %s", s)
		}
		if uq == "" || uq == "0" {
			*d = 0
			return nil
		}
		v, err := ParseDuration(uq)
		if err != nil {
			return err
		}
		*d = Duration(v)
		return nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return fmt.Errorf("invalid duration %s (expected milliseconds)", s)
	}
	if f < 0 {
		return fmt.Errorf("duration %s must not be negative", s)
	}
	if f > float64(math.MaxInt64/int64(time.Millisecond)) {
		return fmt.Errorf("duration %s is too large", s)
	}
	*d = Duration(time.Duration(f * float64(time.Millisecond)))
	return nil
}

// IntList accepts either a single integer or a list of integers in YAML.
type IntList []int

// UnmarshalYAML implements yaml.Unmarshaler.
func (l *IntList) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		var v int
		if err := n.Decode(&v); err != nil {
			return fmt.Errorf("line %d: expected an integer", n.Line)
		}
		*l = IntList{v}
		return nil
	case yaml.SequenceNode:
		var v []int
		if err := n.Decode(&v); err != nil {
			return fmt.Errorf("line %d: expected a list of integers", n.Line)
		}
		*l = IntList(v)
		return nil
	}
	return fmt.Errorf("line %d: expected an integer or a list of integers", n.Line)
}
