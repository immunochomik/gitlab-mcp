package policy

import (
	"testing"
)

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, path string
		expect        bool
	}{
		{"group/repo", "group/repo", true},
		{"group/repo", "group/other", false},
		{"platform/*", "platform/api", true},
		{"platform/*", "platform/api/user", true},       // * spans /
		{"platform/*", "other/api", false},
		{"group/**/stuff", "group/x/y/stuff", true},
		{"group/**/stuff", "group/x/stuff", true},
	}
	for _, cc := range cases {
		got := GlobMatch(cc.pattern, cc.path)
		if got != cc.expect {
			t.Errorf("GlobMatch(%q, %q) = %v, want %v", cc.pattern, cc.path, got, cc.expect)
		}
	}
}
