// Package tools registers the fixed MCP tool catalog and enforces
// policy (action × project) on every invocation.
package tools

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	gitlab "gitlab.com/gitlab-org/api/client-go"

	"gitlab-mcp/internal/audit"
	"gitlab-mcp/internal/config"
	"gitlab-mcp/internal/policy"
	"gitlab-mcp/internal/redact"
)

const (
	defaultLimit     = 20
	maxLimit         = 100
	maxLogBytes      = 256 * 1024
	maxDiffBytes     = 100 * 1024
	maxArtifactBytes = 100 << 20
	maxArtifactFile  = 1 << 20
	maxTreeEntries   = 500
	maxRawFileBytes  = 512 * 1024
	defaultTrivyPat  = `(?i)trivy[^/]*\.(csv|json|txt|md)$`
)

type Tools struct {
	gl      *gitlab.Client
	pol     *policy.Policy
	red     *redact.Redactor
	audit   *audit.Logger
	cfg     *config.Config
	trivyRe *regexp.Regexp
}

func New(gl *gitlab.Client, pol *policy.Policy, red *redact.Redactor, au *audit.Logger, cfg *config.Config) (*Tools, error) {
	pat := cfg.Trivy.FilePattern
	if pat == "" {
		pat = defaultTrivyPat
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		return nil, fmt.Errorf("trivy.file_pattern: %w", err)
	}
	return &Tools{gl: gl, pol: pol, red: red, audit: au, cfg: cfg, trivyRe: re}, nil
}

type handler struct {
	action        string
	fn            func(ctx context.Context, args map[string]any) (string, error)
	needsProject  bool
}

func ptr[T any](v T) *T { return &v }

// RegisterAll registers every catalog action on srv; policy gates them at runtime.
func (t *Tools) RegisterAll(srv *server.MCPServer) {
	for _, s := range t.handlerSpecs() {
		spec := s
		srv.AddTool(t.toolSpec(spec.name), t.wrap(spec))
	}
}

func (t *Tools) wrap(h handlerSpec) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		project, err := t.authorize(h.name, h.proj, args)
		var out string
		if err == nil {
			out, err = h.fn(ctx, args)
		}
		t.audit.Log(h.name, project, args, err)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(out), nil
	}
}

func (t *Tools) authorize(action string, needsProject bool, args map[string]any) (string, error) {
	if !needsProject {
		return "", nil
	}
	project := normalizeProject(t.cfg.GitLab.URL, getString(args, "project"))
	if project == "" {
		return "", errors.New("missing required argument: project")
	}
	if !t.pol.Allowed(action, project) {
		return project, fmt.Errorf("action %q is not permitted for project %q", action, project)
	}
	return project, nil
}

// --- argument helpers ---

func getString(args map[string]any, k string) string {
	v, _ := args[k].(string)
	return v
}

func getInt(args map[string]any, k string) int64 {
	switch v := args[k].(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return n
		}
	}
	return 0
}

func getBool(args map[string]any, k string) bool {
	v, _ := args[k].(bool)
	return v
}

func limitArg(args map[string]any) int64 {
	l := getInt(args, "limit")
	if l <= 0 {
		return defaultLimit
	}
	if l > maxLimit {
		return maxLimit
	}
	return l
}

func normalizeProject(baseURL, p string) string {
	p = strings.Trim(p, "/")
	if baseURL != "" && strings.HasPrefix(p, baseURL) {
		p = strings.TrimPrefix(p, baseURL)
		p = strings.Trim(p, "/")
	}
	if u := baseURL; u != "" && strings.HasPrefix(p, strings.TrimPrefix(u, "https://")) {
		p = strings.TrimPrefix(p, strings.TrimPrefix(u, "https://"))
		p = strings.Trim(p, "/")
	}
	p = strings.TrimSuffix(p, ".git")
	return p
}

func toJSON(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func strOpt(args map[string]any, k string) *string {
	if v := getString(args, k); v != "" {
		return ptr(v)
	}
	return nil
}

// --- handler registry ---

type handlerSpec struct {
	name string
	proj bool
	desc string
	opts []mcp.ToolOption
	fn   func(ctx context.Context, args map[string]any) (string, error)
}

func (t *Tools) handlerSpecs() []handlerSpec {
	return []handlerSpec{
		{name: policy.ListProjects, proj: false, desc: "List GitLab projects permitted by server config (glob patterns)", fn: t.listProjects},
		{name: policy.GetProject, proj: true, desc: "Get project metadata", opts: []mcp.ToolOption{mcp.WithString("project", mcp.Required())}, fn: t.getProject},
		{name: policy.ListBranches, proj: true, desc: "List branches (optionally filtered)", opts: []mcp.ToolOption{mcp.WithString("project", mcp.Required()), mcp.WithString("search"), mcp.WithNumber("limit")}, fn: t.listBranches},
		{name: policy.GetFile, proj: true, desc: "Read a file from the repo at a ref", opts: []mcp.ToolOption{mcp.WithString("project", mcp.Required()), mcp.WithString("path", mcp.Required()), mcp.WithString("ref")}, fn: t.getFile},
		{name: policy.ListTree, proj: true, desc: "List repository tree entries", opts: []mcp.ToolOption{mcp.WithString("project", mcp.Required()), mcp.WithString("path"), mcp.WithString("ref"), mcp.WithBoolean("recursive")}, fn: t.listTree},
		{name: policy.SearchMRs, proj: true, desc: "List/search merge requests in a project (any author)", opts: []mcp.ToolOption{mcp.WithString("project", mcp.Required()), mcp.WithString("state"), mcp.WithString("author"), mcp.WithString("search"), mcp.WithNumber("limit")}, fn: t.searchMRs},
		{name: policy.GetMR, proj: true, desc: "Get merge request details", opts: []mcp.ToolOption{mcp.WithString("project", mcp.Required()), mcp.WithNumber("mr_iid", mcp.Required())}, fn: t.getMR},
		{name: policy.ListMRNotes, proj: true, desc: "List comments/notes on a merge request", opts: []mcp.ToolOption{mcp.WithString("project", mcp.Required()), mcp.WithNumber("mr_iid", mcp.Required()), mcp.WithNumber("limit")}, fn: t.listMRNotes},
		{name: policy.GetMRChanges, proj: true, desc: "Get merge request diff (can be large)", opts: []mcp.ToolOption{mcp.WithString("project", mcp.Required()), mcp.WithNumber("mr_iid", mcp.Required())}, fn: t.getMRChanges},
		{name: policy.CreateMR, proj: true, desc: "Create a merge request (never merges)", opts: []mcp.ToolOption{
			mcp.WithString("project", mcp.Required()), mcp.WithString("title", mcp.Required()), mcp.WithString("source_branch", mcp.Required()), mcp.WithString("target_branch"), mcp.WithString("description"),
		}, fn: t.createMR},
		{name: policy.CreateBranch, proj: true, desc: "Create a branch from a ref (defaults to project default branch)", opts: []mcp.ToolOption{mcp.WithString("project", mcp.Required()), mcp.WithString("branch", mcp.Required()), mcp.WithString("ref")}, fn: t.createBranch},
		{name: policy.CommitFiles, proj: true, desc: `Commit files to a branch. files_json is a JSON array of {"path": "...", "content": "...", "action": "create|update|delete"}`, opts: []mcp.ToolOption{
			mcp.WithString("project", mcp.Required()), mcp.WithString("branch", mcp.Required()), mcp.WithString("commit_message", mcp.Required()), mcp.WithString("files_json", mcp.Required()),
		}, fn: t.commitFiles},
		{name: policy.ListPipelines, proj: true, desc: "List pipelines in a project", opts: []mcp.ToolOption{mcp.WithString("project", mcp.Required()), mcp.WithString("status"), mcp.WithString("ref"), mcp.WithNumber("limit")}, fn: t.listPipelines},
		{name: policy.GetPipeline, proj: true, desc: "Get pipeline status", opts: []mcp.ToolOption{mcp.WithString("project", mcp.Required()), mcp.WithNumber("pipeline_id", mcp.Required())}, fn: t.getPipeline},
		{name: policy.ListPipelineJobs, proj: true, desc: "List jobs of a pipeline", opts: []mcp.ToolOption{mcp.WithString("project", mcp.Required()), mcp.WithNumber("pipeline_id", mcp.Required()), mcp.WithNumber("limit")}, fn: t.listPipelineJobs},
		{name: policy.GetJobLog, proj: true, desc: "Get a job log (secrets redacted per server config)", opts: []mcp.ToolOption{mcp.WithString("project", mcp.Required()), mcp.WithNumber("job_id", mcp.Required())}, fn: t.getJobLog},
		{name: policy.GetTrivyReport, proj: true, desc: "Extract trivy scan report files from a job's artifacts", opts: []mcp.ToolOption{mcp.WithString("project", mcp.Required()), mcp.WithNumber("job_id", mcp.Required())}, fn: t.getTrivyReport},
	}
}

func (t *Tools) toolSpec(name string) mcp.Tool {
	for _, s := range t.handlerSpecs() {
		if s.name == name {
			return mcp.NewTool(name, append([]mcp.ToolOption{mcp.WithDescription(s.desc)}, s.opts...)...)
		}
	}
	return mcp.NewTool(name)
}

// --- implementations ---

type projectSummary struct {
	ID            int64  `json:"id"`
	Path          string `json:"path"`
	Name          string `json:"name"`
	WebURL        string `json:"web_url"`
	DefaultBranch string `json:"default_branch,omitempty"`
}

func (t *Tools) listProjects(ctx context.Context, args map[string]any) (string, error) {
	var out []projectSummary
	var notes []string
	for _, pat := range t.pol.Patterns() {
		if !strings.Contains(pat, "*") {
			p, resp, err := t.gl.Projects.GetProject(pat, nil, gitlab.WithContext(ctx))
			if err != nil {
				notes = append(notes, fmt.Sprintf("pattern %q: %v (HTTP %d)", pat, err, resp.StatusCode))
				continue
			}
			out = append(out, projectSummary{ID: p.ID, Path: p.PathWithNamespace, Name: p.Name, WebURL: p.WebURL, DefaultBranch: p.DefaultBranch})
			continue
		}
		prefix := strings.TrimSuffix(pat[:strings.Index(pat, "*")], "/")
		if prefix == "" {
			notes = append(notes, fmt.Sprintf("pattern %q skipped: needs a literal group prefix before '*'", pat))
			continue
		}
		g, _, err := t.gl.Groups.GetGroup(prefix, nil, gitlab.WithContext(ctx))
		if err != nil {
			notes = append(notes, fmt.Sprintf("pattern %q: group %q: %v", pat, prefix, err))
			continue
		}
		opts := &gitlab.ListGroupProjectsOptions{
			IncludeSubGroups: ptr(true),
			ListOptions:      gitlab.ListOptions{PerPage: 100},
		}
		for page := int64(1); page <= 20; page++ {
			opts.Page = page
			projects, resp, err := t.gl.Groups.ListGroupProjects(g.ID, opts, gitlab.WithContext(ctx))
			if err != nil {
				notes = append(notes, fmt.Sprintf("pattern %q: %v", pat, err))
				break
			}
			for _, p := range projects {
				if policy.GlobMatch(pat, p.PathWithNamespace) {
					out = append(out, projectSummary{ID: p.ID, Path: p.PathWithNamespace, Name: p.Name, WebURL: p.WebURL, DefaultBranch: p.DefaultBranch})
				}
			}
			if resp.NextPage == 0 {
				break
			}
		}
	}
	result := map[string]any{"projects": out}
	if len(notes) > 0 {
		result["notes"] = notes
	}
	return toJSON(result), nil
}

func (t *Tools) getProject(ctx context.Context, args map[string]any) (string, error) {
	p := normalizeProject(t.cfg.GitLab.URL, getString(args, "project"))
	pr, _, err := t.gl.Projects.GetProject(p, nil, gitlab.WithContext(ctx))
	if err != nil {
		return "", err
	}
	type detail struct {
		projectSummary
		Description string `json:"description,omitempty"`
	}
	return toJSON(detail{
		projectSummary: projectSummary{ID: pr.ID, Path: pr.PathWithNamespace, Name: pr.Name, WebURL: pr.WebURL, DefaultBranch: pr.DefaultBranch},
		Description:    pr.Description,
	}), nil
}

func (t *Tools) listBranches(ctx context.Context, args map[string]any) (string, error) {
	p := normalizeProject(t.cfg.GitLab.URL, getString(args, "project"))
	opts := &gitlab.ListBranchesOptions{
		Search:      strOpt(args, "search"),
		ListOptions: gitlab.ListOptions{PerPage: limitArg(args)},
	}
	bs, _, err := t.gl.Branches.ListBranches(p, opts, gitlab.WithContext(ctx))
	if err != nil {
		return "", err
	}
	type b struct {
		Name   string `json:"name"`
		Commit string `json:"commit_id,omitempty"`
	}
	out := []b{}
	for _, br := range bs {
		out = append(out, b{Name: br.Name, Commit: br.Commit.ID})
	}
	return toJSON(out), nil
}

func (t *Tools) getFile(ctx context.Context, args map[string]any) (string, error) {
	p := normalizeProject(t.cfg.GitLab.URL, getString(args, "project"))
	path := getString(args, "path")
	ref := strOpt(args, "ref")
	f, _, err := t.gl.RepositoryFiles.GetFile(p, path, &gitlab.GetFileOptions{Ref: ref}, gitlab.WithContext(ctx))
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(f.Content)
	if err != nil {
		return "", fmt.Errorf("decode file content: %w", err)
	}
	trunc := false
	if len(raw) > maxRawFileBytes {
		raw = raw[:maxRawFileBytes]
		trunc = true
	}
	return toJSON(map[string]any{
		"path":      path,
		"ref":       f.Ref,
		"truncated": trunc,
		"content":   string(raw),
	}), nil
}

func (t *Tools) listTree(ctx context.Context, args map[string]any) (string, error) {
	p := normalizeProject(t.cfg.GitLab.URL, getString(args, "project"))
	opts := &gitlab.ListTreeOptions{
		Path:        strOpt(args, "path"),
		Ref:         strOpt(args, "ref"),
		Recursive:   ptr(getBool(args, "recursive")),
		ListOptions: gitlab.ListOptions{PerPage: maxTreeEntries},
	}
	nodes, _, err := t.gl.Repositories.ListTree(p, opts, gitlab.WithContext(ctx))
	if err != nil {
		return "", err
	}
	type n struct {
		Path string `json:"path"`
		Type string `json:"type"`
	}
	out := []n{}
	trunc := false
	for _, tn := range nodes {
		if len(out) >= maxTreeEntries {
			trunc = true
			break
		}
		out = append(out, n{Path: tn.Path, Type: tn.Type})
	}
	return toJSON(map[string]any{"entries": out, "truncated": trunc}), nil
}

type mrSummary struct {
	IID          int64  `json:"iid"`
	ID           int64  `json:"id"`
	Title        string `json:"title"`
	State        string `json:"state"`
	Author       string `json:"author"`
	SourceBranch string `json:"source_branch"`
	TargetBranch string `json:"target_branch"`
	WebURL       string `json:"web_url"`
	UpdatedAt    string `json:"updated_at,omitempty"`
}

func mrSum(m *gitlab.BasicMergeRequest) mrSummary {
	sum := mrSummary{
		IID: m.IID, ID: m.ID, Title: m.Title, State: m.State,
		SourceBranch: m.SourceBranch, TargetBranch: m.TargetBranch,
		WebURL: m.WebURL,
	}
	if m.Author != nil {
		sum.Author = m.Author.Username
	}
	if m.UpdatedAt != nil {
		sum.UpdatedAt = m.UpdatedAt.Format("2006-01-02 15:04:05 MST")
	}
	return sum
}

func (t *Tools) searchMRs(ctx context.Context, args map[string]any) (string, error) {
	p := normalizeProject(t.cfg.GitLab.URL, getString(args, "project"))
	opts := &gitlab.ListProjectMergeRequestsOptions{
		State:          strOpt(args, "state"),
		AuthorUsername: strOpt(args, "author"),
		Search:         strOpt(args, "search"),
		ListOptions:    gitlab.ListOptions{PerPage: limitArg(args)},
	}
	mrs, _, err := t.gl.MergeRequests.ListProjectMergeRequests(p, opts, gitlab.WithContext(ctx))
	if err != nil {
		return "", err
	}
	out := []mrSummary{}
	for _, m := range mrs {
		out = append(out, mrSum(m))
	}
	return toJSON(out), nil
}

func (t *Tools) getMR(ctx context.Context, args map[string]any) (string, error) {
	p := normalizeProject(t.cfg.GitLab.URL, getString(args, "project"))
	iid := getInt(args, "mr_iid")
	opt := &gitlab.GetMergeRequestsOptions{}
	m, _, err := t.gl.MergeRequests.GetMergeRequest(p, iid, opt, gitlab.WithContext(ctx))
	if err != nil {
		return "", err
	}
	type detail struct {
		mrSummary
		Description string `json:"description,omitempty"`
	}
	return toJSON(detail{mrSummary: mrSum(&m.BasicMergeRequest), Description: m.Description}), nil
}

func (t *Tools) listMRNotes(ctx context.Context, args map[string]any) (string, error) {
	p := normalizeProject(t.cfg.GitLab.URL, getString(args, "project"))
	iid := getInt(args, "mr_iid")
	opts := &gitlab.ListMergeRequestNotesOptions{ListOptions: gitlab.ListOptions{PerPage: limitArg(args)}}
	notes, _, err := t.gl.Notes.ListMergeRequestNotes(p, iid, opts, gitlab.WithContext(ctx))
	if err != nil {
		return "", err
	}
	type note struct {
		ID     int64  `json:"id"`
		Author string `json:"author"`
		Body   string `json:"body"`
	}
	out := []note{}
	for _, n := range notes {
		nt := note{ID: n.ID, Body: n.Body}
		if n.Author.Username != "" {
			nt.Author = n.Author.Username
		}
		out = append(out, nt)
	}
	return toJSON(out), nil
}

func (t *Tools) getMRChanges(ctx context.Context, args map[string]any) (string, error) {
	p := normalizeProject(t.cfg.GitLab.URL, getString(args, "project"))
	iid := getInt(args, "mr_iid")
	diffs, _, err := t.gl.MergeRequests.ListMergeRequestDiffs(p, iid, &gitlab.ListMergeRequestDiffsOptions{ListOptions: gitlab.ListOptions{PerPage: 100}}, gitlab.WithContext(ctx))
	if err != nil {
		return "", err
	}
	var b strings.Builder
	trunc := false
	for _, d := range diffs {
		header := fmt.Sprintf("diff --git a/%s b/%s\n", d.OldPath, d.NewPath)
		if b.Len()+len(header)+len(d.Diff) > maxDiffBytes {
			trunc = true
			break
		}
		b.WriteString(header)
		b.WriteString(d.Diff)
		b.WriteString("\n")
	}
	return toJSON(map[string]any{"diff": b.String(), "truncated": trunc}), nil
}

func (t *Tools) createMR(ctx context.Context, args map[string]any) (string, error) {
	p := normalizeProject(t.cfg.GitLab.URL, getString(args, "project"))
	opts := &gitlab.CreateMergeRequestOptions{
		Title:        ptr(getString(args, "title")),
		SourceBranch: ptr(getString(args, "source_branch")),
		TargetBranch: strOpt(args, "target_branch"),
		Description:  strOpt(args, "description"),
	}
	m, _, err := t.gl.MergeRequests.CreateMergeRequest(p, opts, gitlab.WithContext(ctx))
	if err != nil {
		return "", err
	}
	return toJSON(mrSum(&m.BasicMergeRequest)), nil
}

func (t *Tools) createBranch(ctx context.Context, args map[string]any) (string, error) {
	p := normalizeProject(t.cfg.GitLab.URL, getString(args, "project"))
	name := getString(args, "branch")
	ref := getString(args, "ref")
	if ref == "" {
		pr, _, err := t.gl.Projects.GetProject(p, nil, gitlab.WithContext(ctx))
		if err != nil {
			return "", fmt.Errorf("resolve default branch: %w", err)
		}
		ref = pr.DefaultBranch
		if ref == "" {
			return "", fmt.Errorf("project has no default branch; pass 'ref'")
		}
	}
	br, _, err := t.gl.Branches.CreateBranch(p, &gitlab.CreateBranchOptions{
		Branch: ptr(name),
		Ref:    ptr(ref),
	}, gitlab.WithContext(ctx))
	if err != nil {
		return "", err
	}
	return toJSON(map[string]any{"branch": br.Name, "commit": br.Commit.ID}), nil
}

type fileAction struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Action  string `json:"action"` // create | update | delete (default: create)
}

func (t *Tools) commitFiles(ctx context.Context, args map[string]any) (string, error) {
	p := normalizeProject(t.cfg.GitLab.URL, getString(args, "project"))
	branch := getString(args, "branch")
	msg := getString(args, "commit_message")
	var files []fileAction
	if err := json.Unmarshal([]byte(getString(args, "files_json")), &files); err != nil {
		return "", fmt.Errorf("files_json must be a JSON array of {\"path\":..., \"content\":..., \"action\":create|update|delete}: %w", err)
	}
	if len(files) == 0 {
		return "", errors.New("files_json contained no files")
	}
	var actions []*gitlab.CommitActionOptions
	for _, f := range files {
		if f.Path == "" {
			return "", errors.New("file entry missing path")
		}
		ca := &gitlab.CommitActionOptions{FilePath: ptr(f.Path)}
		switch f.Action {
		case "", "create":
			ca.Action = ptr(gitlab.FileCreate)
			ca.Content = ptr(f.Content)
		case "update":
			ca.Action = ptr(gitlab.FileUpdate)
			ca.Content = ptr(f.Content)
		case "delete":
			ca.Action = ptr(gitlab.FileDelete)
		default:
			return "", fmt.Errorf("unknown file action %q", f.Action)
		}
		actions = append(actions, ca)
	}
	c, _, err := t.gl.Commits.CreateCommit(p, &gitlab.CreateCommitOptions{
		Branch:        ptr(branch),
		CommitMessage: ptr(msg),
		Actions:       actions,
	}, gitlab.WithContext(ctx))
	if err != nil {
		return "", err
	}
	return toJSON(map[string]any{"commit_id": c.ID, "branch": branch, "message": c.Message}), nil
}

type pipelineSummary struct {
	ID     int64  `json:"id"`
	Status string `json:"status"`
	Ref    string `json:"ref"`
	SHA    string `json:"sha"`
	WebURL string `json:"web_url"`
}

func (t *Tools) listPipelines(ctx context.Context, args map[string]any) (string, error) {
	p := normalizeProject(t.cfg.GitLab.URL, getString(args, "project"))
	opts := &gitlab.ListProjectPipelinesOptions{
		Ref:         strOpt(args, "ref"),
		ListOptions: gitlab.ListOptions{PerPage: limitArg(args)},
	}
	if s := getString(args, "status"); s != "" {
		v := gitlab.BuildStateValue(s)
		opts.Status = &v
	}
	pls, _, err := t.gl.Pipelines.ListProjectPipelines(p, opts, gitlab.WithContext(ctx))
	if err != nil {
		return "", err
	}
	out := []pipelineSummary{}
	for _, pl := range pls {
		out = append(out, pipelineSummary{ID: pl.ID, Status: pl.Status, Ref: pl.Ref, SHA: pl.SHA, WebURL: pl.WebURL})
	}
	return toJSON(out), nil
}

func (t *Tools) getPipeline(ctx context.Context, args map[string]any) (string, error) {
	p := normalizeProject(t.cfg.GitLab.URL, getString(args, "project"))
	pid := getInt(args, "pipeline_id")
	pl, _, err := t.gl.Pipelines.GetPipeline(p, pid, gitlab.WithContext(ctx))
	if err != nil {
		return "", err
	}
	return toJSON(pipelineSummary{ID: pl.ID, Status: pl.Status, Ref: pl.Ref, SHA: pl.SHA, WebURL: pl.WebURL}), nil
}

type jobSummary struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Stage  string `json:"stage"`
	Status string `json:"status"`
	WebURL string `json:"web_url"`
}

func (t *Tools) listPipelineJobs(ctx context.Context, args map[string]any) (string, error) {
	p := normalizeProject(t.cfg.GitLab.URL, getString(args, "project"))
	pid := getInt(args, "pipeline_id")
	opts := &gitlab.ListJobsOptions{ListOptions: gitlab.ListOptions{PerPage: limitArg(args)}}
	jobs, _, err := t.gl.Jobs.ListPipelineJobs(p, pid, opts, gitlab.WithContext(ctx))
	if err != nil {
		return "", err
	}
	out := []jobSummary{}
	for _, j := range jobs {
		out = append(out, jobSummary{ID: j.ID, Name: j.Name, Stage: j.Stage, Status: j.Status, WebURL: j.WebURL})
	}
	return toJSON(out), nil
}

func (t *Tools) getJobLog(ctx context.Context, args map[string]any) (string, error) {
	p := normalizeProject(t.cfg.GitLab.URL, getString(args, "project"))
	jobID := getInt(args, "job_id")
	r, _, err := t.gl.Jobs.GetTraceFile(p, jobID, gitlab.WithContext(ctx))
	if err != nil {
		return "", err
	}
	data, err := io.ReadAll(io.LimitReader(r, maxLogBytes+1))
	if err != nil {
		return "", err
	}
	trunc := len(data) > maxLogBytes
	if trunc {
		data = data[:maxLogBytes]
	}
	out := t.red.Redact(string(data))
	return toJSON(map[string]any{"job_id": jobID, "truncated": trunc, "log": out}), nil
}

func (t *Tools) getTrivyReport(ctx context.Context, args map[string]any) (string, error) {
	p := normalizeProject(t.cfg.GitLab.URL, getString(args, "project"))
	jobID := getInt(args, "job_id")
	r, _, err := t.gl.Jobs.GetJobArtifacts(p, jobID, gitlab.WithContext(ctx))
	if err != nil {
		return "", err
	}
	data, err := io.ReadAll(io.LimitReader(r, maxArtifactBytes+1))
	if err != nil {
		return "", err
	}
	if len(data) > maxArtifactBytes {
		return "", fmt.Errorf("artifact archive exceeds %d bytes", maxArtifactBytes)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", fmt.Errorf("artifact archive is not a zip: %w", err)
	}
	var names []string
	type hit struct{ name, content string }
	var hits []hit
	for _, f := range zr.File {
		names = append(names, f.Name)
		if !t.trivyRe.MatchString(f.Name) {
			continue
		}
		if f.UncompressedSize64 > maxArtifactFile {
			hits = append(hits, hit{name: f.Name, content: "(skipped: file too large)"})
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return "", err
		}
		b, err := io.ReadAll(io.LimitReader(rc, maxArtifactFile))
		_ = rc.Close()
		if err != nil {
			return "", err
		}
		hits = append(hits, hit{name: f.Name, content: t.red.Redact(string(b))})
	}
	if len(hits) == 0 {
		return "", fmt.Errorf("no artifact matching %q found; archive contains: %s", t.trivyRe.String(), strings.Join(names, ", "))
	}
	result := []map[string]any{}
	for _, h := range hits {
		result = append(result, map[string]any{"file": h.name, "content": h.content})
	}
	return toJSON(result), nil
}
