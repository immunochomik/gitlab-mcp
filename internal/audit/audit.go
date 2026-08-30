// Package audit writes a JSONL record of every tool call.
package audit

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"gitlab-mcp/internal/config"
)

type entry struct {
	Time    string         `json:"time"`
	Tool    string         `json:"tool"`
	Project string         `json:"project,omitempty"`
	OK      bool           `json:"ok"`
	Err     string         `json:"error,omitempty"`
	Args    map[string]any `json:"args,omitempty"`
}

type Logger struct {
	mu  sync.Mutex
	f   *os.File
	enc *json.Encoder
}

func New(path string) (*Logger, error) {
	if path == "" {
		return &Logger{}, nil
	}
	p := config.ExpandHome(path)
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	return &Logger{f: f, enc: json.NewEncoder(f)}, nil
}

// Log records one tool invocation. Argument string values are truncated.
func (l *Logger) Log(tool, project string, args map[string]any, err error) {
	if l.f == nil {
		return
	}
	red := map[string]any{}
	for k, v := range args {
		if s, ok := v.(string); ok && len(s) > 300 {
			red[k] = s[:300] + "…"
		} else {
			red[k] = v
		}
	}
	e := entry{
		Time:    time.Now().UTC().Format(time.RFC3339),
		Tool:    tool,
		Project: project,
		OK:      err == nil,
		Args:    red,
	}
	if err != nil {
		e.Err = err.Error()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.enc.Encode(e)
}

func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		_ = l.f.Close()
	}
}
