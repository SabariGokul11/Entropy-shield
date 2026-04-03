🛡️ EntropyShield
Entropy-based secret scanner with automatic HashiCorp Vault remediation.
EntropyShield detects secrets before they reach the cloud — not just by looking for known patterns like `AKIA...`, but by calculating the randomness (Shannon entropy) of every token in your code. High-entropy strings are statistically unlikely to be human-written text; they're almost certainly generated credentials.
When a secret is found, EntropyShield can automatically:
Store the real value in HashiCorp Vault (KV v2)
Rewrite your source file with a proper `os.Getenv(...)` / `process.env.X` reference
Block the git push via pre-commit / pre-push hooks
Annotate your GitHub PR with findings and upload SARIF to Code Scanning
---
How Shannon Entropy Works
For a string `s`, entropy is calculated as:
```
H(s) = -Σ p(x) · log₂ p(x)
```
Where `p(x)` is the probability of each character. The range is `[0, log₂(alphabet_size)]`.
String example	Entropy	Verdict
`password`	2.75	✅ Safe (word)
`hello world`	3.10	✅ Safe (prose)
`AKIAIOSFODNN7EXAMPLE`	4.09	🚨 CRITICAL
`wJalrXUtnFEMI/K7MDENG/bPxRfiCY`	5.52	🚨 CRITICAL
`ghp_ABCDEFGHIJKLMNabcdef123456`	5.11	🚨 CRITICAL
---
Quick Start
Install
```bash
go install github.com/entropy-shield/cmd@latest
```
Run a scan
```bash
# Scan the current git diff
entropy-shield scan

# Scan specific files
entropy-shield scan config.go api/client.go

# Scan + auto-vault (moves secrets to Vault, rewrites files)
export VAULT_ADDR=https://vault.example.com:8200
export VAULT_TOKEN=hvs.xxx
entropy-shield scan --auto-vault --vault-path secret/myproject
```
Install git hooks
```bash
entropy-shield install
# Installs .git/hooks/pre-commit and .git/hooks/pre-push
```
Suppress a false positive
Add `# entropy-shield:ignore` to any line:
```python
EXAMPLE_KEY = "aB3kL9mN2pQ7rS4tU6vW1z"  # entropy-shield:ignore
```
---
GitHub Actions
Copy `.github/workflows/entropy-scan.yml` into your repository. The workflow:
Runs on every push and PR
Scans only changed files (not the whole repo) for speed
Uploads SARIF results to GitHub Code Scanning (visible in the Security tab)
Comments on PRs with finding details
Blocks the merge if secrets are detected
Required secrets (for auto-remediation job):
Secret	Value
`VAULT_ADDR`	Your Vault server URL
`VAULT_TOKEN`	A token with the `entropy-shield` policy
---
Vault Integration
Bootstrap locally
```bash
./scripts/setup-vault.sh
```
This starts a local Vault dev server, enables KV v2, applies the minimum-privilege policy, and prints the env vars to use.
Apply policy to production Vault
```bash
vault policy write entropy-shield configs/vault-policy.hcl
```
What gets stored
For each detected secret, EntropyShield writes a KV v2 entry at:
```
secret/entropy-shield/<repo>/<filename>_<type>_L<line>
```
With the following fields:
```json
{
  "value":    "<raw secret>",
  "type":     "AWS_ACCESS_KEY",
  "source":   "config/aws.go:42",
  "env_var":  "SECRET_AWS_ACCESS_KEY_0042",
  "entropy":  "5.2134",
  "severity": "CRITICAL"
}
```
---
Configuration
Create `.entropy-shield.yaml` in your repo root:
```yaml
min_entropy: 4.5

extensions:
  - .go
  - .py
  - .js
  - .env
  - .tf

allowlist:
  - "example\\.com"
  - "YOUR_API_KEY_HERE"
  - "localhost"
```
---
Detected Secret Types
Type	Pattern	Entropy Threshold
`AWS_ACCESS_KEY`	`AKIA[0-9A-Z]{16}`	3.5
`AWS_SECRET_KEY`	40-char base64	4.8
`GITHUB_TOKEN`	`ghp_[0-9a-zA-Z]{36}`	4.0
`JWT`	`eyJ...` three-part	5.0
`STRIPE_KEY`	`sk_live_` / `sk_test_`	3.8
`PRIVATE_KEY`	`-----BEGIN * PRIVATE KEY-----`	0.0 (always)
`DATABASE_URL`	`postgres://user:pass@`	0.0 (always)
`GENERIC_HIGH_ENTROPY`	Any 16–256 char token	`min_entropy` (default 4.5)
---
Architecture
```
git diff / file paths
        │
        ▼
┌──────────────────┐
│  scanner.Scanner │  Shannon entropy scoring
│  + knownPatterns │  + 8 regex pattern rules
└────────┬─────────┘
         │ []Finding
         ▼
┌──────────────────┐
│ reporter.Print   │  ANSI terminal output
│ reporter.SARIF   │  GitHub Code Scanning
└────────┬─────────┘
         │ (--auto-vault)
         ▼
┌──────────────────┐
│  vault.Client    │  KV v2 write via HTTP API
└────────┬─────────┘
         │ secretKey
         ▼
┌──────────────────┐
│ replacer.Replace │  Rewrites source files with
│ InFile()         │  os.Getenv("SECRET_...") refs
└──────────────────┘
```
---
License
MIT