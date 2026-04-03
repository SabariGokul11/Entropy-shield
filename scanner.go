package scanner

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

// ─── Types ────────────────────────────────────────────────────────────────────

// Config holds scanner tunables loaded from CLI flags or .entropy-shield.yaml.
type Config struct {
	MinEntropy float64  `yaml:"min_entropy"`
	ConfigFile string   `yaml:"-"`
	Allowlist  []string `yaml:"allowlist"` // regex patterns to skip
	Extensions []string `yaml:"extensions"` // file extensions to scan
}

// Finding represents a single detected secret candidate.
type Finding struct {
	File     string
	Line     int
	Match    string       // the high-entropy token
	Context  string       // surrounding code line
	Entropy  float64      // Shannon entropy score
	Type     SecretType   // classified type (AKID, JWT, generic, …)
	Severity Severity
}

// EnvVarName derives a clean environment variable name from the finding.
func (f Finding) EnvVarName() string {
	base := strings.ToUpper(string(f.Type))
	suffix := fmt.Sprintf("_%04d", f.Line)
	return "SECRET_" + base + suffix
}

type SecretType string

const (
	TypeAWSAccessKey    SecretType = "AWS_ACCESS_KEY"
	TypeAWSSecretKey    SecretType = "AWS_SECRET_KEY"
	TypeGitHubToken     SecretType = "GITHUB_TOKEN"
	TypeJWT             SecretType = "JWT"
	TypeStripeKey       SecretType = "STRIPE_KEY"
	TypeGCPServiceAcct  SecretType = "GCP_SERVICE_ACCOUNT"
	TypePrivateKey      SecretType = "PRIVATE_KEY"
	TypeGenericHighEntr SecretType = "GENERIC_HIGH_ENTROPY"
	TypeDatabaseURL     SecretType = "DATABASE_URL"
)

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
)

// ─── Patterns ────────────────────────────────────────────────────────────────

type patternRule struct {
	re       *regexp.Regexp
	typ      SecretType
	severity Severity
	minEntr  float64 // override global minimum for this type
}

var knownPatterns = []patternRule{
	{
		re:       regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`),
		typ:      TypeAWSAccessKey,
		severity: SeverityCritical,
		minEntr:  3.5,
	},
	{
		re:       regexp.MustCompile(`(?i)(aws.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]`),
		typ:      TypeAWSSecretKey,
		severity: SeverityCritical,
		minEntr:  4.8,
	},
	{
		re:       regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`),
		typ:      TypeGitHubToken,
		severity: SeverityCritical,
		minEntr:  4.0,
	},
	{
		re:       regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}`),
		typ:      TypeJWT,
		severity: SeverityHigh,
		minEntr:  5.0,
	},
	{
		re:       regexp.MustCompile(`sk_(live|test)_[0-9a-zA-Z]{24,}`),
		typ:      TypeStripeKey,
		severity: SeverityCritical,
		minEntr:  3.8,
	},
	{
		re:       regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`),
		typ:      TypePrivateKey,
		severity: SeverityCritical,
		minEntr:  0.0, // always flag
	},
	{
		re:       regexp.MustCompile(`(?i)(postgres|mysql|mongodb|redis)://[^@\s]+:[^@\s]+@`),
		typ:      TypeDatabaseURL,
		severity: SeverityCritical,
		minEntr:  0.0,
	},
}

// high-entropy token extraction: split on whitespace and common delimiters
var tokenSplitter = regexp.MustCompile(`[\s=:"'\x60,{}\[\]()<>|&;]+`)

// ─── Scanner ─────────────────────────────────────────────────────────────────

// Scanner is the main scanning engine.
type Scanner struct {
	cfg       Config
	allowlist []*regexp.Regexp
}

// New creates a Scanner. If cfg.ConfigFile exists it merges yaml config.
func New(cfg Config) *Scanner {
	_ = cfg.loadFile() // ignore missing file
	s := &Scanner{cfg: cfg}
	for _, pat := range cfg.Allowlist {
		if re, err := regexp.Compile(pat); err == nil {
			s.allowlist = append(s.allowlist, re)
		}
	}
	return s
}

func (c *Config) loadFile() error {
	data, err := os.ReadFile(c.ConfigFile)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, c)
}

// ─── Public scan surfaces ─────────────────────────────────────────────────────

// ScanFiles scans a list of explicit file paths.
func (s *Scanner) ScanFiles(paths []string) ([]Finding, error) {
	var all []Finding
	for _, p := range paths {
		findings, err := s.scanFile(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: skipping %s: %v\n", p, err)
			continue
		}
		all = append(all, findings...)
	}
	return all, nil
}

// ScanGitDiff scans the unstaged + staged diff vs HEAD.
func (s *Scanner) ScanGitDiff() ([]Finding, error) {
	return s.runGitDiff("HEAD")
}

// ScanStagedDiff scans only staged (index) changes — for pre-commit hooks.
func (s *Scanner) ScanStagedDiff() ([]Finding, error) {
	return s.runGitDiff("--cached")
}

// InstallHooks writes pre-commit and pre-push scripts into .git/hooks/.
func InstallHooks() error {
	hooks := map[string]string{
		".git/hooks/pre-commit": preCommitHook,
		".git/hooks/pre-push":   prePushHook,
	}
	for path, content := range hooks {
		if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
			return fmt.Errorf("failed to write %s: %w", path, err)
		}
		fmt.Printf("✅ Installed hook: %s\n", path)
	}
	return nil
}

// ─── Internal ─────────────────────────────────────────────────────────────────

func (s *Scanner) runGitDiff(ref string) ([]Finding, error) {
	args := []string{"diff", ref, "--unified=0", "--diff-filter=A", "--text"}
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return nil, fmt.Errorf("git diff: %w", err)
	}
	return s.parseDiff(string(out))
}

func (s *Scanner) parseDiff(diff string) ([]Finding, error) {
	var findings []Finding
	currentFile := ""
	lineNum := 0

	scanner := bufio.NewScanner(strings.NewReader(diff))
	for scanner.Scan() {
		line := scanner.Text()

		// Track which file we're in
		if strings.HasPrefix(line, "+++ b/") {
			currentFile = strings.TrimPrefix(line, "+++ b/")
			continue
		}
		if strings.HasPrefix(line, "@@ ") {
			// parse line number: @@ -a,b +c,d @@
			fmt.Sscanf(line, "@@ -%*d,%*d +%d", &lineNum)
			continue
		}
		if !strings.HasPrefix(line, "+") || strings.HasPrefix(line, "+++") {
			if strings.HasPrefix(line, " ") {
				lineNum++
			}
			continue
		}

		// This is an added line
		lineNum++
		addedLine := strings.TrimPrefix(line, "+")

		fs := s.scanLine(currentFile, lineNum, addedLine)
		findings = append(findings, fs...)
	}
	return findings, nil
}

func (s *Scanner) scanFile(path string) ([]Finding, error) {
	if !s.shouldScanExtension(path) {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var findings []Finding
	lineNum := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lineNum++
		findings = append(findings, s.scanLine(path, lineNum, sc.Text())...)
	}
	return findings, nil
}

// scanLine is the hot path — called for every added diff line.
func (s *Scanner) scanLine(file string, lineNum int, line string) []Finding {
	// Skip comments
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
		return nil
	}

	if s.isAllowlisted(line) {
		return nil
	}

	var findings []Finding

	// 1. Known pattern matching (fast path)
	for _, rule := range knownPatterns {
		matches := rule.re.FindAllString(line, -1)
		for _, m := range matches {
			entropy := shannonEntropy(m)
			if entropy < rule.minEntr {
				continue
			}
			findings = append(findings, Finding{
				File:     file,
				Line:     lineNum,
				Match:    redact(m),
				Context:  truncate(line, 120),
				Entropy:  entropy,
				Type:     rule.typ,
				Severity: rule.severity,
			})
		}
	}

	// 2. Generic entropy scan — tokenise the line and score each token
	tokens := tokenSplitter.Split(line, -1)
	for _, tok := range tokens {
		if !isEntropyCandidate(tok) {
			continue
		}
		entropy := shannonEntropy(tok)
		if entropy < s.cfg.MinEntropy {
			continue
		}
		if alreadyFound(findings, tok) {
			continue
		}
		findings = append(findings, Finding{
			File:     file,
			Line:     lineNum,
			Match:    redact(tok),
			Context:  truncate(line, 120),
			Entropy:  entropy,
			Type:     TypeGenericHighEntr,
			Severity: severityFromEntropy(entropy),
		})
	}

	return findings
}

// ─── Shannon Entropy ─────────────────────────────────────────────────────────

// shannonEntropy computes H = -Σ p(x) log₂ p(x) for the input string.
// Returns a value in [0, log₂(|alphabet|)]. For base64-like strings this
// tends to be 5–6; for human-readable words it's 2–4.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}
	n := float64(len([]rune(s)))
	var h float64
	for _, count := range freq {
		p := count / n
		h -= p * math.Log2(p)
	}
	return h
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// isEntropyCandidate filters obvious non-secrets (URLs, common words, short tokens).
func isEntropyCandidate(tok string) bool {
	if len(tok) < 16 || len(tok) > 256 {
		return false
	}
	if strings.Contains(tok, "://") {
		return false
	}
	// Must contain at least one digit and one letter (passwords usually do)
	hasDigit := false
	hasLetter := false
	for _, r := range tok {
		if unicode.IsDigit(r) {
			hasDigit = true
		}
		if unicode.IsLetter(r) {
			hasLetter = true
		}
	}
	return hasDigit && hasLetter
}

func severityFromEntropy(e float64) Severity {
	switch {
	case e >= 5.5:
		return SeverityCritical
	case e >= 4.5:
		return SeverityHigh
	default:
		return SeverityMedium
	}
}

func (s *Scanner) isAllowlisted(line string) bool {
	for _, re := range s.allowlist {
		if re.MatchString(line) {
			return true
		}
	}
	// Inline suppression comment
	return strings.Contains(line, "entropy-shield:ignore")
}

func (s *Scanner) shouldScanExtension(path string) bool {
	if len(s.cfg.Extensions) == 0 {
		return true
	}
	ext := strings.ToLower(filepath.Ext(path))
	for _, e := range s.cfg.Extensions {
		if e == ext {
			return true
		}
	}
	return false
}

func redact(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + strings.Repeat("*", len(s)-8) + s[len(s)-4:]
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func alreadyFound(findings []Finding, tok string) bool {
	for _, f := range findings {
		if strings.Contains(f.Match, tok[:4]) {
			return true
		}
	}
	return false
}

// ─── Git Hook Scripts ─────────────────────────────────────────────────────────

const preCommitHook = `#!/bin/sh
# EntropyShield pre-commit hook
# Installed by: entropy-shield install

entropy-shield hook --staged
if [ $? -ne 0 ]; then
  echo ""
  echo "💡 To skip: git commit --no-verify (not recommended)"
  exit 1
fi
`

const prePushHook = `#!/bin/sh
# EntropyShield pre-push hook
# Installed by: entropy-shield install

entropy-shield hook
if [ $? -ne 0 ]; then
  echo ""
  echo "💡 Run: entropy-shield scan --auto-vault to auto-remediate"
  exit 1
fi
`
