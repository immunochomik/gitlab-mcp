package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	GitLab   GitLabConfig     `yaml:"gitlab"`
	Server   ServerConfig     `yaml:"server"`
	Defaults PolicyRules      `yaml:"defaults"`
	Projects []ProjectRule    `yaml:"projects"`
	Redaction RedactionConfig `yaml:"redaction"`
	Trivy    TrivyConfig      `yaml:"trivy"`
	Audit    AuditConfig      `yaml:"audit"`
}

type GitLabConfig struct {
	URL       string `yaml:"url"`
	TokenEnv  string `yaml:"token_env"`
	TokenFile string `yaml:"token_file"`
}

type ServerConfig struct {
	Transport string `yaml:"transport"` // "stdio" or "http"
	Listen    string `yaml:"listen"`    // for http, default 127.0.0.1:8787
}

type PolicyRules struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

// ProjectRule grants access to projects whose full path (group/subgroup/repo)
// matches Group, where '*' is a wildcard spanning any characters including '/'.
type ProjectRule struct {
	Group string   `yaml:"group"`
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

type RedactionConfig struct {
	Enabled  *bool           `yaml:"enabled"`  // default true
	Patterns []string        `yaml:"patterns"` // custom regexes, replaced with [REDACTED]
	Entropy  EntropyConfig   `yaml:"entropy"`
}

type EntropyConfig struct {
	Enabled   bool    `yaml:"enabled"`
	MinLength int     `yaml:"min_length"` // default 20
	Threshold float64 `yaml:"threshold"`  // default 4.5 bits/char
}

type TrivyConfig struct {
	// FilePattern matches artifact file names to extract. Default:
	// (?i)trivy[^/]*\.(csv|json|txt)
	FilePattern string `yaml:"file_pattern"`
}

type AuditConfig struct {
	File string `yaml:"file"` // JSONL audit log; empty disables
}

// Load reads and validates the configuration file.
func Load(path string) (*Config, error) {
	p := ExpandHome(path)
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", p, err)
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.Server.Transport == "" {
		c.Server.Transport = "http"
	}
	if c.Server.Listen == "" {
		c.Server.Listen = "127.0.0.1:8787"
	}
	if c.Redaction.Enabled == nil {
		t := true
		c.Redaction.Enabled = &t
	}
	if c.Redaction.Entropy.MinLength == 0 {
		c.Redaction.Entropy.MinLength = 20
	}
	if c.Redaction.Entropy.Threshold == 0 {
		c.Redaction.Entropy.Threshold = 4.5
	}
}

func (c *Config) validate() error {
	if c.GitLab.URL == "" {
		return fmt.Errorf("gitlab.url is required")
	}
	if c.GitLab.TokenEnv == "" && c.GitLab.TokenFile == "" {
		return fmt.Errorf("gitlab.token_env or gitlab.token_file is required")
	}
	if c.Server.Transport != "stdio" && c.Server.Transport != "http" {
		return fmt.Errorf("server.transport must be stdio or http")
	}
	if len(c.Projects) == 0 {
		return fmt.Errorf("at least one projects entry is required (default-deny without it)")
	}
	return nil
}

// Token resolves the GitLab token from the configured source.
func (c *Config) Token() (string, error) {
	if c.GitLab.TokenFile != "" {
		p := ExpandHome(c.GitLab.TokenFile)
		b, err := os.ReadFile(p)
		if err != nil {
			return "", fmt.Errorf("read token file: %w", err)
		}
		tok := strings.TrimSpace(string(b))
		if tok == "" {
			return "", fmt.Errorf("token file %s is empty", p)
		}
		return tok, nil
	}
	tok := os.Getenv(c.GitLab.TokenEnv)
	if tok == "" {
		return "", fmt.Errorf("environment variable %s is not set or empty", c.GitLab.TokenEnv)
	}
	return tok, nil
}

func ExpandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}
