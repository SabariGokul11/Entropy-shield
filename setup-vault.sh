#!/usr/bin/env bash
# scripts/setup-vault.sh
# Bootstraps a local Vault dev server for testing EntropyShield.
# Usage: ./scripts/setup-vault.sh

set -euo pipefail

VAULT_DEV_TOKEN="root"
VAULT_PORT=8200
ES_POLICY="entropy-shield"
KV_PATH="secret"

echo "🔐 Starting Vault dev server..."
vault server -dev \
  -dev-root-token-id="$VAULT_DEV_TOKEN" \
  -dev-listen-address="127.0.0.1:${VAULT_PORT}" &
VAULT_PID=$!
sleep 2

export VAULT_ADDR="http://127.0.0.1:${VAULT_PORT}"
export VAULT_TOKEN="$VAULT_DEV_TOKEN"

echo "✅ Vault is running (PID $VAULT_PID)"
echo "   VAULT_ADDR=$VAULT_ADDR"
echo "   VAULT_TOKEN=$VAULT_TOKEN"

# Enable KV v2
echo ""
echo "📦 Enabling KV v2 at $KV_PATH/..."
vault secrets enable -path="$KV_PATH" kv-v2 2>/dev/null || true

# Apply policy
echo "📜 Writing EntropyShield policy..."
vault policy write "$ES_POLICY" configs/vault-policy.hcl

# Create a scoped token for EntropyShield
echo "🎫 Creating scoped token..."
ES_TOKEN=$(vault token create \
  -policy="$ES_POLICY" \
  -ttl="24h" \
  -format=json | jq -r '.auth.client_token')

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🚀 Setup complete! Use these env vars:"
echo ""
echo "  export VAULT_ADDR=$VAULT_ADDR"
echo "  export VAULT_TOKEN=$ES_TOKEN"
echo ""
echo "  # Test the scanner + vault integration:"
echo "  go run ./cmd/main.go scan \\"
echo "    --auto-vault \\"
echo "    --vault-path secret/entropy-shield \\"
echo "    testdata/sample_secrets.go"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Keep vault running
wait $VAULT_PID
