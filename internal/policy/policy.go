// Package policy implements the action allow/deny decision engine.
// Actions are a fixed catalog; projects are matched by glob patterns.
// Resolution: any matching project rule denying the action wins; otherwise
// any matching rule allowing it wins; otherwise fall back to defaults.
// If no project pattern matches the requested project path, the action is
// denied (default-deny) regardless of defaults.
package policy

import (
	"fmt"
	"regexp"
	"strings"

	"gitlab-mcp/internal/config"
)

// Catalog is the closed set of actions that can be exposed as MCP tools.
const (
	ListProjects     = "list_projects"
	GetProject       = "get_project"
	ListBranches     = "list_branches"
	GetFile          = "get_file"
	ListTree         = "list_tree"
	SearchMRs        = "search_mrs"
	GetMR            = "get_mr"
	ListMRNotes      = "list_mr_notes"
	GetMRChanges     = "get_mr_changes"
	CreateMR         = "create_mr"
	CreateBranch     = "create_branch"
	CommitFiles      = "commit_files"
	ListPipelines    = "list_pipelines"
	GetPipeline      = "get_pipeline"
	ListPipelineJobs = "list_pipeline_jobs"
	GetJobLog        = "get_job_log"
	GetTrivyReport   = "get_trivy_report"
)

// All is the full action catalog.
var All = []string{
	ListProjects, GetProject, ListBranches, GetFile, ListTree,
	SearchMRs, GetMR, ListMRNotes, GetMRChanges, CreateMR,
	CreateBranch, CommitFiles,
	ListPipelines, GetPipeline, ListPipelineJobs, GetJobLog, GetTrivyReport,
}

type Policy struct {
	cfg *config.Config
}

func New(cfg *config.Config) *Policy { return &Policy{cfg: cfg} }

// Allowed decides whether action may run on projectPath.
// list_projects is treated specially: it operates on the configured patterns
// themselves and is allowed whenever any pattern exists; its output is
// restricted to matched patterns regardless.
func (p *Policy) Allowed(action, projectPath string) bool {
	if action == ListProjects {
		return len(p.cfg.Projects) > 0
	}
	matched := false
	allow := inDefaults(p.cfg.Defaults, action)
	for _, rule := range p.cfg.Projects {
		if GlobMatch(rule.Group, projectPath) {
			matched = true
			if contains(rule.Deny, action) {
				return false
			}
			if contains(rule.Allow, action) {
				allow = true
			}
		}
	}
	if !matched {
		return false
	}
	return allow
}

// Patterns returns the configured project patterns.
func (p *Policy) Patterns() []string {
	out := make([]string, 0, len(p.cfg.Projects))
	for _, r := range p.cfg.Projects {
		out = append(out, r.Group)
	}
	return out
}

func inDefaults(d config.PolicyRules, action string) bool {
	if contains(d.Deny, action) {
		return false
	}
	return contains(d.Allow, action)
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// GlobMatch matches pattern against path where '*' spans any characters
// (including '/'). Matching is exact otherwise.
func GlobMatch(pattern, path string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == path
	}
	var b strings.Builder
	b.WriteString("^")
	for _, r := range pattern {
		if r == '*' {
			b.WriteString(".*")
		} else {
			fmt.Fprintf(&b, "%s", regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return false
	}
	return re.MatchString(path)
}
