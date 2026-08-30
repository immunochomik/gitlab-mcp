package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/mark3labs/mcp-go/server"

	gitlab "gitlab.com/gitlab-org/api/client-go"

	"gitlab-mcp/internal/audit"
	"gitlab-mcp/internal/config"
	"gitlab-mcp/internal/policy"
	"gitlab-mcp/internal/redact"
	"gitlab-mcp/internal/tools"
)

const version = "0.1.0"

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

	token, err := cfg.Token()
	if err != nil {
		log.Fatalf("token: %v", err)
	}

	gl, err := gitlab.NewClient(token, gitlab.WithBaseURL(cfg.GitLab.URL))
	if err != nil {
		log.Fatalf("gitlab client: %v", err)
	}

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
		if err := server.ServeStdio(srv); err != nil {
			log.Fatalf("serve stdio: %v", err)
		}
	case "http":
		httpSrv := server.NewStreamableHTTPServer(srv)
		log.Printf("gitlab-mcp %s listening on %s (streamable HTTP)", version, cfg.Server.Listen)
		if err := httpSrv.Start(cfg.Server.Listen); err != nil {
			log.Fatalf("serve http: %v", err)
		}
	default:
		log.Fatalf("unknown transport %q", cfg.Server.Transport)
	}
	os.Exit(0)
}
