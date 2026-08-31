package config

import (
	"strings"
	"testing"
)

func TestBasicAuth(t *testing.T) {
	t.Setenv("GITLAB_USER", "alice")
	t.Setenv("GITLAB_PASSWORD", "secret")
	c := &Config{GitLab: GitLabConfig{UserEnv: "GITLAB_USER", PasswordEnv: "GITLAB_PASSWORD"}}

	configured, user, password, err := c.BasicAuth()
	if err != nil {
		t.Fatal(err)
	}
	if !configured || user != "alice" || password != "secret" {
		t.Fatalf("BasicAuth() = %v, %q, %q; want true, alice, secret", configured, user, password)
	}
}

func TestBasicAuthMissingEnvironmentVariable(t *testing.T) {
	t.Setenv("GITLAB_USER", "alice")
	c := &Config{GitLab: GitLabConfig{UserEnv: "GITLAB_USER", PasswordEnv: "MISSING_GITLAB_PASSWORD"}}

	_, _, _, err := c.BasicAuth()
	if err == nil || !strings.Contains(err.Error(), "MISSING_GITLAB_PASSWORD") {
		t.Fatalf("BasicAuth() error = %v; want missing password environment variable", err)
	}
}

func TestValidateAcceptsBasicAuthAndRejectsPartialConfiguration(t *testing.T) {
	c := &Config{
		GitLab:   GitLabConfig{URL: "https://gitlab.example.com", UserEnv: "GITLAB_USER", PasswordEnv: "GITLAB_PASSWORD"},
		Server:   ServerConfig{Transport: "http"},
		Projects: []ProjectRule{{Group: "group/*"}},
	}
	if err := c.validate(); err != nil {
		t.Fatalf("validate() error = %v", err)
	}

	c.GitLab.PasswordEnv = ""
	if err := c.validate(); err == nil {
		t.Fatal("validate() succeeded with only gitlab.user_env configured")
	}
}
