package main

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"gitlab-mcp/internal/config"

	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func TestNewGitLabClientUsesBasicAuth(t *testing.T) {
	t.Setenv("GITLAB_USER", "alice")
	t.Setenv("GITLAB_PASSWORD", "secret")

	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := `{"id":1,"username":"alice"}`
		if r.URL.Path == "/oauth/token" {
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if r.Form.Get("username") != "alice" || r.Form.Get("password") != "secret" {
				t.Errorf("OAuth credentials = %q, %q; want alice, secret", r.Form.Get("username"), r.Form.Get("password"))
			}
			body = `{"access_token":"oauth-token","token_type":"bearer","expires_in":3600}`
		} else if got := r.Header.Get("Authorization"); got != "Bearer oauth-token" {
			t.Errorf("Authorization = %q; want Bearer oauth-token", got)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    r,
		}, nil
	})

	cfg := &config.Config{GitLab: config.GitLabConfig{
		URL: "https://gitlab.example.com", UserEnv: "GITLAB_USER", PasswordEnv: "GITLAB_PASSWORD",
	}}
	client, err := newGitLabClient(cfg, gitlab.WithHTTPClient(&http.Client{Transport: transport}))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.Users.CurrentUser(); err != nil {
		t.Fatal(err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
