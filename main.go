package main

import (
	"fmt"
	"os"

	"github.com/entropy-shield/internal/reporter"
	"github.com/entropy-shield/internal/scanner"
	"github.com/entropy-shield/internal/vault"
	"github.com/spf13/cobra"
)

var (
	vaultAddr  string
	vaultToken string
	vaultPath  string
	autoVault  bool
	minEntropy float64
	configFile string
	staged     bool
)

var rootCmd = &cobra.Command{
	Use:   "entropy-shield",
	Short: "Entropy-based secret scanner with HashiCorp Vault integration",
	Long: `EntropyShield scans git diffs for high-entropy strings that may be secrets,
API keys, or credentials — then automatically moves them to HashiCorp Vault
and replaces them with environment variable references in your code.`,
}

var scanCmd = &cobra.Command{
	Use:   "scan [files...]",
	Short: "Scan files or git diff for secrets",
	RunE:  runScan,
}

var hookCmd = &cobra.Command{
	Use:   "hook",
	Short: "Run as a pre-push / pre-commit git hook",
	RunE:  runHook,
}

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install git hooks into the current repository",
	RunE:  runInstall,
}

func init() {
	scanCmd.Flags().StringVar(&vaultAddr, "vault-addr", os.Getenv("VAULT_ADDR"), "HashiCorp Vault address")
	scanCmd.Flags().StringVar(&vaultToken, "vault-token", os.Getenv("VAULT_TOKEN"), "Vault token")
	scanCmd.Flags().StringVar(&vaultPath, "vault-path", "secret/entropy-shield", "Vault KV path prefix")
	scanCmd.Flags().BoolVar(&autoVault, "auto-vault", false, "Automatically move secrets to Vault and rewrite files")
	scanCmd.Flags().Float64Var(&minEntropy, "min-entropy", 4.5, "Minimum Shannon entropy score to flag (0-8)")
	scanCmd.Flags().StringVar(&configFile, "config", ".entropy-shield.yaml", "Config file path")

	hookCmd.Flags().BoolVar(&staged, "staged", true, "Scan only staged (git add) changes")
	hookCmd.Flags().StringVar(&vaultAddr, "vault-addr", os.Getenv("VAULT_ADDR"), "HashiCorp Vault address")
	hookCmd.Flags().BoolVar(&autoVault, "auto-vault", false, "Automatically remediate secrets")

	rootCmd.AddCommand(scanCmd, hookCmd, installCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	cfg := scanner.Config{
		MinEntropy: minEntropy,
		ConfigFile: configFile,
	}

	sc := scanner.New(cfg)

	var findings []scanner.Finding
	var err error

	if len(args) == 0 {
		fmt.Println("📡 Scanning git diff (HEAD)...")
		findings, err = sc.ScanGitDiff()
	} else {
		fmt.Printf("📡 Scanning %d file(s)...\n", len(args))
		findings, err = sc.ScanFiles(args)
	}

	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if len(findings) == 0 {
		fmt.Println("✅ No secrets detected.")
		return nil
	}

	reporter.PrintFindings(findings)

	if autoVault && vaultAddr != "" {
		return remediateWithVault(findings)
	}

	if len(findings) > 0 {
		os.Exit(1) // fail CI/CD pipeline
	}
	return nil
}

func runHook(cmd *cobra.Command, args []string) error {
	cfg := scanner.Config{MinEntropy: 4.5}
	sc := scanner.New(cfg)

	findings, err := sc.ScanStagedDiff()
	if err != nil {
		return err
	}

	if len(findings) == 0 {
		return nil // allow push
	}

	reporter.PrintFindings(findings)
	fmt.Fprintf(os.Stderr, "\n🚫 Push blocked: %d potential secret(s) detected.\n", len(findings))
	fmt.Fprintf(os.Stderr, "   Run with --auto-vault to remediate automatically.\n")
	os.Exit(1)
	return nil
}

func runInstall(cmd *cobra.Command, args []string) error {
	return scanner.InstallHooks()
}

func remediateWithVault(findings []scanner.Finding) error {
	vc, err := vault.NewClient(vault.Config{
		Address: vaultAddr,
		Token:   vaultToken,
		Path:    vaultPath,
	})
	if err != nil {
		return fmt.Errorf("vault connection failed: %w", err)
	}

	fmt.Printf("\n🔐 Remediating %d finding(s) with Vault...\n", len(findings))

	for _, f := range findings {
		secretKey, err := vc.StoreSecret(f)
		if err != nil {
			fmt.Printf("  ❌ Failed to vault %s: %v\n", f.Match, err)
			continue
		}
		fmt.Printf("  ✅ Stored → %s (env: %s)\n", secretKey, f.EnvVarName())
	}

	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
