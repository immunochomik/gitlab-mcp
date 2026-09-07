package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
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

func TestPipelineToolSchemasExposeNewArguments(t *testing.T) {
	tools := testTools(t, "https://gitlab.example.com")
	for _, tc := range []struct {
		name string
		want []string
	}{
		{policy.ListPipelineJobs, []string{"scope", "include_retried", "include_bridges", "follow_downstream", "max_depth", "page", "limit"}},
		{policy.GetJobLog, []string{"offset", "limit"}},
	} {
		spec := tools.toolSpec(tc.name)
		for _, property := range tc.want {
			if _, ok := spec.InputSchema.Properties[property]; !ok {
				t.Errorf("%s schema is missing %q", tc.name, property)
			}
		}
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
