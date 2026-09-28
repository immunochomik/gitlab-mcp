package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	gitlab "gitlab.com/gitlab-org/api/client-go"

	"gitlab-mcp/internal/config"
	"gitlab-mcp/internal/policy"
	"gitlab-mcp/internal/redact"
)

func testTools(t *testing.T, serverURL string) *Tools {
	t.Helper()
	client, err := gitlab.NewClient("test-token", gitlab.WithBaseURL(serverURL))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		GitLab:   config.GitLabConfig{URL: serverURL},
		Defaults: config.PolicyRules{Allow: []string{policy.ListPipelineJobs, policy.GetJobLog}},
		Projects: []config.ProjectRule{{Group: "group/*"}},
	}
	redactor, err := redact.New(config.RedactionConfig{})
	if err != nil {
		t.Fatal(err)
	}
	tools, err := New(client, policy.New(cfg), redactor, nil, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return tools
}

func TestToolSchemasExposeNewArguments(t *testing.T) {
	tools := testTools(t, "https://gitlab.example.com")
	for _, tc := range []struct {
		name string
		want []string
	}{
		{policy.ListPipelines, []string{"page", "limit", "created_after", "created_before", "updated_after", "updated_before"}},
		{policy.GetJob, []string{"project", "job_id"}},
		{policy.ListPipelineJobs, []string{"scope", "include_retried", "include_bridges", "follow_downstream", "max_depth", "page", "limit"}},
		{policy.GetJobLog, []string{"offset", "limit"}},
		{policy.CreateMRNote, []string{"project", "mr_iid", "body"}},
	} {
		spec := tools.toolSpec(tc.name)
		for _, property := range tc.want {
			if _, ok := spec.InputSchema.Properties[property]; !ok {
				t.Errorf("%s schema is missing %q", tc.name, property)
			}
		}
	}
}

func TestCreateMRNote(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodPost || r.URL.Path != "/api/v4/projects/group/root/merge_requests/42/notes" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		var payload struct {
			Body string `json:"body"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload.Body != "Please check the migration." {
			t.Errorf("body = %q", payload.Body)
		}
		fmt.Fprint(w, `{"id":123,"body":"Please check the migration."}`)
	}))
	defer server.Close()
	tools := testTools(t, server.URL)
	args := map[string]any{"project": "group/root", "mr_iid": 42, "body": "Please check the migration."}
	if _, err := tools.authorize(policy.CreateMRNote, true, args); err == nil {
		t.Fatal("create_mr_note should require explicit permission")
	}
	tools.cfg.Defaults.Allow = append(tools.cfg.Defaults.Allow, policy.CreateMRNote)
	if _, err := tools.authorize(policy.CreateMRNote, true, args); err != nil {
		t.Fatal(err)
	}
	if _, err := tools.authorize(policy.CreateMRNote, true, map[string]any{"project": "other/root"}); err == nil {
		t.Fatal("create_mr_note allowed an unconfigured project")
	}
	for _, invalid := range []map[string]any{
		{"project": "group/root", "mr_iid": 0, "body": "hello"},
		{"project": "group/root", "mr_iid": 42, "body": "  "},
	} {
		if _, err := tools.createMRNote(context.Background(), invalid); err == nil {
			t.Errorf("expected validation error for %#v", invalid)
		}
	}
	if requests != 0 {
		t.Fatalf("invalid input sent %d requests", requests)
	}
	out, err := tools.createMRNote(context.Background(), args)
	if err != nil {
		t.Fatal(err)
	}
	var note struct {
		ID   int64  `json:"id"`
		Body string `json:"body"`
	}
	if err := json.Unmarshal([]byte(out), &note); err != nil {
		t.Fatal(err)
	}
	if requests != 1 || note.ID != 123 || note.Body != "Please check the migration." {
		t.Fatalf("requests = %d, note = %#v", requests, note)
	}
}

func TestListPipelinesPaginationAndDateFilters(t *testing.T) {
	filters := map[string]string{
		"created_after": "2026-09-01T00:00:00Z", "created_before": "2026-09-14T00:00:00Z",
		"updated_after": "2026-09-02T00:00:00Z", "updated_before": "2026-09-15T00:00:00Z",
		"status": "failed", "ref": "main",
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v4/projects/group/root/pipelines" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		for key, want := range filters {
			if got := r.URL.Query().Get(key); got != want {
				t.Errorf("%s = %q, want %q", key, got, want)
			}
		}
		if got := r.URL.Query().Get("per_page"); got != "100" {
			t.Errorf("per_page = %q, want 100", got)
		}
		switch r.URL.Query().Get("page") {
		case "2":
			fmt.Fprint(w, `[{"id":7,"ref":"main","status":"failed"}]`)
		case "3":
			fmt.Fprint(w, `[]`)
		default:
			t.Errorf("unexpected page: %s", r.URL.RawQuery)
		}
	}))
	defer server.Close()
	args := map[string]any{"project": "group/root", "page": 2, "limit": 200}
	for key, value := range filters {
		args[key] = value
	}
	tools := testTools(t, server.URL)
	out, err := tools.listPipelines(context.Background(), args)
	if err != nil {
		t.Fatal(err)
	}
	var pipelines []pipelineSummary
	if err := json.Unmarshal([]byte(out), &pipelines); err != nil || len(pipelines) != 1 || pipelines[0].ID != 7 {
		t.Fatalf("unexpected pipelines: %s, error: %v", out, err)
	}
	args["page"] = 3
	if out, err := tools.listPipelines(context.Background(), args); err != nil || out != "[]" {
		t.Fatalf("last page = %q, error: %v", out, err)
	}
}

func TestListPipelinesRejectsInvalidDates(t *testing.T) {
	tools := testTools(t, "https://gitlab.example.com")
	for _, field := range []string{"created_after", "created_before", "updated_after", "updated_before"} {
		for _, value := range []any{"yesterday", "2026-09-01", "", 123} {
			_, err := tools.listPipelines(context.Background(), map[string]any{"project": "group/root", field: value})
			if err == nil || !strings.Contains(err.Error(), field+" must be an RFC3339 timestamp") {
				t.Errorf("%s=%v: error = %v", field, value, err)
			}
		}
	}
}

func TestGetJobReturnsExactNameAndPipeline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v4/projects/group/root/jobs/987" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		fmt.Fprint(w, `{"id":987,"name":"deploy: [saas, prod]","stage":"deploy","status":"failed","ref":"main","web_url":"https://gitlab.example.com/group/root/-/jobs/987","pipeline":{"id":321,"project_id":8,"ref":"main","sha":"abc","status":"failed"}}`)
	}))
	defer server.Close()
	out, err := testTools(t, server.URL).getJob(context.Background(), map[string]any{"project": "group/root", "job_id": 987})
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		jobSummary
		Ref      string          `json:"ref"`
		Pipeline pipelineSummary `json:"pipeline"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	if result.ID != 987 || result.Name != "deploy: [saas, prod]" || result.Stage != "deploy" || result.Status != "failed" || result.PipelineID != 321 || result.Pipeline.ID != 321 || result.Pipeline.ProjectID != 8 || result.Pipeline.SHA != "abc" || result.Ref != "main" {
		t.Fatalf("unexpected job: %s", out)
	}
}

func TestGetJobPolicyAndErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"404 Job Not Found"}`, http.StatusNotFound)
	}))
	defer server.Close()
	tools := testTools(t, server.URL)
	args := map[string]any{"project": "group/root", "job_id": 987}
	if _, err := tools.authorize(policy.GetJob, true, args); err == nil {
		t.Fatal("get_job should require explicit permission")
	}
	tools.cfg.Defaults.Allow = append(tools.cfg.Defaults.Allow, policy.GetJob)
	if _, err := tools.authorize(policy.GetJob, true, args); err != nil {
		t.Fatal(err)
	}
	if _, err := tools.authorize(policy.GetJob, true, map[string]any{"project": "other/root"}); err == nil {
		t.Fatal("get_job allowed an unconfigured project")
	}
	if _, err := tools.getJob(context.Background(), args); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("expected upstream 404, got %v", err)
	}
	args["job_id"] = 0
	if _, err := tools.getJob(context.Background(), args); err == nil || err.Error() != "job_id must be a positive integer" {
		t.Fatalf("expected invalid ID error, got %v", err)
	}
}

func TestListPipelineJobsPassesScopeAndIncludeRetried(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.URL.Path, "/api/v4/projects/group/root/pipelines/42/jobs"; got != want {
			t.Errorf("path = %q, want %q", got, want)
		}
		query := r.URL.Query()
		if got, want := query["scope[]"], []string{"failed", "success"}; !reflect.DeepEqual(got, want) {
			t.Errorf("scope = %#v, want %#v", got, want)
		}
		if got := query.Get("include_retried"); got != "true" {
			t.Errorf("include_retried = %q, want true", got)
		}
		if got := query.Get("page"); got != "2" {
			t.Errorf("page = %q, want 2", got)
		}
		if got := query.Get("per_page"); got != "75" {
			t.Errorf("per_page = %q, want 75", got)
		}
		fmt.Fprint(w, `[{"id":9,"name":"test","stage":"test","status":"failed"}]`)
	}))
	defer server.Close()

	out, err := testTools(t, server.URL).listPipelineJobs(context.Background(), map[string]any{
		"project": "group/root", "pipeline_id": int64(42),
		"scope": []any{"failed", "success"}, "include_retried": true,
		"page": int64(2), "limit": int64(75),
	})
	if err != nil {
		t.Fatal(err)
	}
	var jobs []jobSummary
	if err := json.Unmarshal([]byte(out), &jobs); err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].ID != 9 || jobs[0].Status != "failed" {
		t.Fatalf("jobs = %#v", jobs)
	}
}

func TestListPipelineJobsFollowsDownstreamBridge(t *testing.T) {
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v4/projects/group/root/pipelines/10/jobs":
			fmt.Fprint(w, `[{"id":1,"name":"parent","status":"success"}]`)
		case "/api/v4/projects/group/root/pipelines/10/bridges":
			fmt.Fprintf(w, `[{"id":2,"name":"child","status":"success","downstream_pipeline":{"id":20,"project_id":8,"status":"failed","web_url":%q}}]`, serverURL+"/group/child/-/pipelines/20")
		case "/api/v4/projects/group/child/pipelines/20/jobs":
			fmt.Fprint(w, `[{"id":3,"name":"child-test","stage":"test","status":"failed"}]`)
		case "/api/v4/projects/group/child/pipelines/20/bridges":
			fmt.Fprint(w, `[]`)
		default:
			http.Error(w, "unexpected path: "+r.URL.Path, http.StatusNotFound)
		}
	}))
	serverURL = server.URL
	defer server.Close()

	out, err := testTools(t, server.URL).listPipelineJobs(context.Background(), map[string]any{
		"project": "group/root", "pipeline_id": int64(10), "follow_downstream": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var jobs []jobSummary
	if err := json.Unmarshal([]byte(out), &jobs); err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 3 {
		t.Fatalf("got %d entries, want parent job, bridge, and child job: %s", len(jobs), out)
	}
	if jobs[1].Kind != "bridge" || jobs[1].DownstreamPipeline == nil || jobs[1].DownstreamPipeline.Project != "group/child" {
		t.Fatalf("bridge metadata = %#v", jobs[1])
	}
	if jobs[2].Kind != "job" || jobs[2].Project != "group/child" || jobs[2].PipelineID != 20 {
		t.Fatalf("child job = %#v", jobs[2])
	}
}

func TestGetJobLogUsesRangeAndReturnsNextOffset(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.URL.Path, "/api/v4/projects/group/root/jobs/7/trace"; got != want {
			t.Errorf("path = %q, want %q", got, want)
		}
		if got, want := r.Header.Get("Range"), "bytes=5-8"; got != want {
			t.Errorf("Range = %q, want %q", got, want)
		}
		w.Header().Set("Content-Range", "bytes 5-8/12")
		w.WriteHeader(http.StatusPartialContent)
		fmt.Fprint(w, "fghi")
	}))
	defer server.Close()

	out, err := testTools(t, server.URL).getJobLog(context.Background(), map[string]any{
		"project": "group/root", "job_id": int64(7), "offset": int64(5), "limit": int64(4),
	})
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Offset        int64  `json:"offset"`
		ReturnedBytes int64  `json:"returned_bytes"`
		NextOffset    int64  `json:"next_offset"`
		TotalBytes    int64  `json:"total_bytes"`
		Truncated     bool   `json:"truncated"`
		Log           string `json:"log"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	if result.Offset != 5 || result.ReturnedBytes != 4 || result.NextOffset != 9 || result.TotalBytes != 12 || !result.Truncated || result.Log != "fghi" {
		t.Fatalf("result = %#v", result)
	}
}

func TestGetJobLogSlicesLocallyWhenServerIgnoresRange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "abcdefghijkl")
	}))
	defer server.Close()

	out, err := testTools(t, server.URL).getJobLog(context.Background(), map[string]any{
		"project": "group/root", "job_id": int64(7), "offset": int64(8), "limit": int64(4),
	})
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	if result["log"] != "ijkl" || result["truncated"] != false || result["total_bytes"] != float64(12) {
		t.Fatalf("result = %#v", result)
	}
}
