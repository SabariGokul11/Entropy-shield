# vault-policy.hcl
# Minimum-privilege Vault policy for EntropyShield.
# Apply with: vault policy write entropy-shield vault-policy.hcl

# Read/write to the entropy-shield KV v2 path
path "secret/data/entropy-shield/*" {
  capabilities = ["create", "update", "read"]
}

path "secret/metadata/entropy-shield/*" {
  capabilities = ["list", "read"]
}

# Allow health-check
path "sys/health" {
  capabilities = ["read"]
}

