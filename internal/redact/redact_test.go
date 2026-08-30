package redact

import (
	"strings"
	"testing"

	"gitlab-mcp/internal/config"
)

func TestBuiltins(t *testing.T) {
	cfg := config.RedactionConfig{Enabled: &tTrue}
	r, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		input, expect string
	}{
		{"use token glpat-abc123def456ghi", "use token " + mask},
		{"token=glpat-abc123def456ghi", "token=" + mask},
		{"AKIA123456789ABCDEFG", mask},
		{"Authorization: Bearer some_jwt_token", "Authorization: Bearer " + mask},
		{"password: mysecret123", "password: " + mask},
		{"SECRET=abc123", "SECRET=" + mask},
		{"-----BEGIN RSA PRIVATE KEY-----\ndata\n-----END RSA PRIVATE KEY-----", mask},
		{"eyJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoidGVzdCJ9.abcdefghijklmnop", mask},
		{"normal text with no secrets", "normal text with no secrets"},
	}
	for _, tt := range tests {
		got := r.Redact(tt.input)
		if got != tt.expect {
			t.Errorf("Redact(%q) = %q, want %q", tt.input, got, tt.expect)
		}
	}
}

func TestCustomPattern(t *testing.T) {
	cfg := config.RedactionConfig{
		Enabled:  &tTrue,
		Patterns: []string{`\bCUSTOM-[A-Z0-9]{6}\b`},
	}
	r, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	out := r.Redact("my CUSTOM-ABCDEF key")
	if !strings.Contains(out, mask) {
		t.Errorf("expected redaction, got %q", out)
	}
}

func TestEntropy(t *testing.T) {
	cfg := config.RedactionConfig{
		Enabled: &tTrue,
		Entropy: config.EntropyConfig{Enabled: true, MinLength: 15, Threshold: 3.5},
	}
	r, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// high-entropy base64-ish string
	high := "aB3dEfGhIjKlMnOpQrStUvWxYz1234567890"
	out := r.Redact("entropy " + high + " end")
	if !strings.Contains(out, mask) {
		t.Errorf("expected high-entropy string redacted, got %q", out)
	}
	// low-entropy repeated char
	low := "aaaaaaaaaaaaaaa"
	out = r.Redact("low " + low)
	if strings.Contains(out, mask) {
		t.Errorf("low entropy should not be redacted, got %q", out)
	}
}

func TestDisabled(t *testing.T) {
	cfg := config.RedactionConfig{Enabled: &tFalse}
	r, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if r.Redact("glpat-anything") != "glpat-anything" {
		t.Error("redaction should be disabled")
	}
}

var tTrue, tFalse = true, false
