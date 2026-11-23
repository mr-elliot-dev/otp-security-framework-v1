package config

import (
	"encoding/json"
	"errors"
	"os"
	"time"
)

type Config struct {
	AllowlistedDomains []string      `json:"allowlisted_domains"`
	Target             string        `json:"target"`
	OTPEndpoint        string        `json:"otp_endpoint"`
	VerifyEndpoint     string        `json:"verify_endpoint"`
	Timeout            time.Duration `json:"-"`
	TimeoutSec         int           `json:"timeout_seconds"`
	MaxRequests        int           `json:"max_requests"`
	RequestsPerSecond  int           `json:"requests_per_second"`
	UserAgent          string        `json:"user_agent"`
	ReportDir          string        `json:"report_dir"`
	Verbose            bool          `json:"verbose"`
}

func Default() *Config {
	return &Config{
		Timeout:           10 * time.Second,
		TimeoutSec:        10,
		MaxRequests:       200,
		RequestsPerSecond: 5,
		UserAgent:         "otpsec/1.0 (authorized-security-testing)",
		ReportDir:         "reports",
		AllowlistedDomains: []string{"localhost", "127.0.0.1"},
	}
}

func Load(path string) (*Config, error) {
	cfg := Default()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, err
		}
	}
	if cfg.TimeoutSec > 0 {
		cfg.Timeout = time.Duration(cfg.TimeoutSec) * time.Second
	}
	return cfg, nil
}

// Validate enforces authorization safety: target must be allowlisted.
func (c *Config) Validate() error {
	if c.Target == "" {
		return errors.New("target required")
	}
	host := hostOf(c.Target)
	ok := false
	for _, d := range c.AllowlistedDomains {
		if host == d {
			ok = true
			break
		}
	}
	if !ok {
		return errors.New("target not in allowlisted_domains — refuse to run (safety)")
	}
	if c.MaxRequests <= 0 || c.MaxRequests > 1000 {
		return errors.New("max_requests must be between 1 and 1000")
	}
	return nil
}

func hostOf(raw string) string {
	// minimal URL host extraction
	for i := 0; i < len(raw); i++ {
		if raw[i] == ':' && i+2 < len(raw) && raw[i+1] == '/' && raw[i+2] == '/' {
			rest := raw[i+3:]
			for j := 0; j < len(rest); j++ {
				if rest[j] == '/' || rest[j] == ':' {
					return rest[:j]
				}
			}
			return rest
		}
	}
	return raw
}