package main

import (
	_ "embed"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/mark3labs/mcp-go/server"

	gitlab "gitlab.com/gitlab-org/api/client-go"

	"gitlab-mcp/internal/audit"
	"gitlab-mcp/internal/config"
	"gitlab-mcp/internal/policy"
	"gitlab-mcp/internal/redact"
	"gitlab-mcp/internal/tools"
)

//go:embed VERSION
var versionFile string

var version = strings.TrimSpace(versionFile)

func main() {
	cfgPath := flag.String("config", "~/.config/gitlab-mcp/config.yaml", "path to config YAML")
	transport := flag.String("transport", "", "override config server.transport (stdio|http)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("gitlab-mcp " + version)
		return
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if *transport != "" {
		cfg.Server.Transport = *transport
	}

	gl, err := newGitLabClient(cfg)
	if err != nil {
		log.Fatalf("gitlab client: %v", err)
	}

	// startup check: verify GitLab connectivity
	if err := checkGitLab(gl, cfg); err != nil {
		log.Fatalf("GitLab connectivity check failed: %v", err)
	}
	log.Println("GitLab connection OK")

	red, err := redact.New(cfg.Redaction)
	if err != nil {
		log.Fatalf("redaction config: %v", err)
	}

	au, err := audit.New(cfg.Audit.File)
	if err != nil {
		log.Fatalf("audit: %v", err)
	}
	defer au.Close()

	pol := policy.New(cfg)

	t, err := tools.New(gl, pol, red, au, cfg)
	if err != nil {
		log.Fatalf("tools: %v", err)
	}

	srv := server.NewMCPServer("gitlab-mcp", version,
		server.WithToolCapabilities(true))
	t.RegisterAll(srv)

	switch cfg.Server.Transport {
	case "stdio":
		log.Println("gitlab-mcp starting on stdio")
		if err := server.ServeStdio(srv); err != nil {
			log.Fatalf("serve stdio: %v", err)
		}
	case "http":
		mcpHandler := server.NewStreamableHTTPServer(srv,
			server.WithStreamableHTTPLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
				Level: slog.LevelInfo,
			}))),
		)
		// wrap with error-logging middleware
		wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			lrw := &loggingResponseWriter{ResponseWriter: w, status: 200}
			mcpHandler.ServeHTTP(lrw, r)
			if lrw.status >= 400 {
				log.Printf("HTTP %d: %s %s (remote %s)", lrw.status, r.Method, r.URL, r.RemoteAddr)
			}
		})
		httpSrv := &http.Server{
			Addr:    cfg.Server.Listen,
			Handler: wrapped,
		}
		log.Printf("gitlab-mcp %s listening on %s (streamable HTTP)", version, cfg.Server.Listen)
		if err := httpSrv.ListenAndServe(); err != nil {
			log.Fatalf("serve http: %v", err)
		}
	default:
		log.Fatalf("unknown transport %q", cfg.Server.Transport)
	}
	os.Exit(0)
}

func newGitLabClient(cfg *config.Config, options ...gitlab.ClientOptionFunc) (*gitlab.Client, error) {
	options = append(options, gitlab.WithBaseURL(cfg.GitLab.URL))
	basic, user, password, err := cfg.BasicAuth()
	if err != nil {
		return nil, fmt.Errorf("basic auth: %w", err)
	}
	if basic {
		return gitlab.NewBasicAuthClient(user, password, options...)
	}
	token, err := cfg.Token()
	if err != nil {
		return nil, fmt.Errorf("token: %w", err)
	}
	return gitlab.NewClient(token, options...)
}

// checkGitLab verifies the token works by fetching the current user.
func checkGitLab(gl *gitlab.Client, cfg *config.Config) error {
	user, _, err := gl.Users.CurrentUser()
	if err != nil {
		return fmt.Errorf("current user: %w", err)
	}
	log.Printf("  gitlab user: %s (%s)", user.Username, user.Name)
	return nil
}

type loggingResponseWriter struct {
	http.ResponseWriter
	status int
}

func (l *loggingResponseWriter) WriteHeader(code int) {
	l.status = code
	l.ResponseWriter.WriteHeader(code)
}
