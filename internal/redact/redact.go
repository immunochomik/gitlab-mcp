package redact

import (
	"math"
	"regexp"
	"strconv"

	"gitlab-mcp/internal/config"
)

const mask = "[REDACTED]"

type rule struct {
	re   *regexp.Regexp
	tmpl string
}

var builtins = []struct {
	pattern string
	tmpl    string
}{
	{`\b(?:glpat|glrt|glpc|glso|gloas)-[A-Za-z0-9_\-]{8,}`, mask},
	{`\b(?:AKIA|ASIA)[0-9A-Z]{16}`, mask},
	{`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}`, mask},
	{`\bgithub_pat_[A-Za-z0-9_]{20,}`, mask},
	{`\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+`, mask},
	{`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`, mask},
	{`(?i)(authorization\s*:\s*bearer\s+)[^\s"']+`, `$1` + mask},
	{`(?i)\b(password|passwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|private[_-]?key|aws[_-]?secret)(\s*[=:]\s*["']?)[^\s"']+`, `$1$2` + mask},
}

type Redactor struct {
	enabled bool
	rules   []rule
	entropy *config.EntropyConfig
	tokenRe *regexp.Regexp
}

func New(cfg config.RedactionConfig) (*Redactor, error) {
	r := &Redactor{enabled: cfg.Enabled != nil && *cfg.Enabled}
	if !r.enabled {
		return r, nil
	}
	for _, b := range builtins {
		re, err := regexp.Compile(b.pattern)
		if err != nil {
			return nil, err
		}
		r.rules = append(r.rules, rule{re: re, tmpl: b.tmpl})
	}
	for _, p := range cfg.Patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, err
		}
		r.rules = append(r.rules, rule{re: re, tmpl: mask})
	}
	if cfg.Entropy.Enabled {
		e := cfg.Entropy
		r.entropy = &e
		r.tokenRe = regexp.MustCompile(`[A-Za-z0-9/_+=\-]{` + strconv.Itoa(e.MinLength) + `,}`)
	}
	return r, nil
}

func (r *Redactor) Redact(s string) string {
	if !r.enabled {
		return s
	}
	for _, rl := range r.rules {
		s = rl.re.ReplaceAllString(s, rl.tmpl)
	}
	if r.entropy != nil && r.tokenRe != nil {
		s = r.tokenRe.ReplaceAllStringFunc(s, func(tok string) string {
			if shannon(tok) >= r.entropy.Threshold {
				return mask
			}
			return tok
		})
	}
	return s
}

func shannon(s string) float64 {
	counts := map[rune]int{}
	for _, c := range s {
		counts[c]++
	}
	n := float64(len(s))
	var e float64
	for _, c := range counts {
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}
