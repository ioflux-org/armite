#!/usr/bin/env bash
# The SDK smoke scripts against a running server: token, ARM, Key
# Vault, Storage. Installs the pinned dependencies first (npm ci).
set -euo pipefail
CI_DIR="${CI_DIR:-/tmp/armite-ci}"
export NODE_EXTRA_CA_CERTS="$CI_DIR/home/ca.pem"
export AZURE_AUTHORITY_HOST=https://login.localhost:8443
export AZURE_TENANT_ID=11111111-1111-1111-1111-111111111111
export AZURE_CLIENT_ID=33333333-3333-3333-3333-333333333333
export AZURE_CLIENT_SECRET=armite-secret
(cd scripts/sdk-smoke && npm ci --silent)
for script in smoke arm-smoke keyvault-smoke blob-smoke; do
    echo "--- $script.mjs"
    node "scripts/sdk-smoke/$script.mjs"
done
