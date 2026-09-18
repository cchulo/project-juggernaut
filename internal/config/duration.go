package config

import (
	"encoding/json"
	"fmt"
	"time"
)

// UnmarshalJSON accepts Go duration strings ("15m") and, for convenience, bare
// integers interpreted as seconds.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch t := v.(type) {
	case string:
		if t == "" {
			d.Duration = 0
			return nil
		}
		parsed, err := time.ParseDuration(t)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", t, err)
		}
		d.Duration = parsed
	case float64:
		d.Duration = time.Duration(t) * time.Second
	default:
		return fmt.Errorf("invalid duration value %v", v)
	}
	return nil
}

// MarshalJSON renders the duration as a Go duration string.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.Duration.String())
}

// Or returns d, or def when d is zero.
func (d Duration) Or(def time.Duration) time.Duration {
	if d.Duration == 0 {
		return def
	}
	return d.Duration
}

// Quantity is a Kubernetes resource quantity that may be written as a bare
// number in YAML (cpu: 1) or a string (cpu: 500m).
type Quantity string

// UnmarshalJSON accepts strings and numbers.
func (q *Quantity) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch t := v.(type) {
	case string:
		*q = Quantity(t)
	case float64:
		*q = Quantity(fmt.Sprintf("%g", t))
	default:
		return fmt.Errorf("invalid quantity %v", v)
	}
	return nil
}

// String returns the quantity text.
func (q Quantity) String() string { return string(q) }
