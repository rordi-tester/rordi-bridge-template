#!/usr/bin/env bash
# RD-14142 — deploy both spike Workers into the DISPOSABLE Cloudflare account.
#
# Run under `rordi secrets exec` so RORDI_TEST_CF_* are in the environment.
# Never echoes a secret: values are passed to curl via a metadata file built
# with a heredoc, and the file is removed on exit.
set -euo pipefail

: "${RORDI_TEST_CF_ACCOUNT:?}" "${RORDI_TEST_CF_KEY:?}"
[ "${RORDI_TEST_CF_ACCOUNT}" = "${CLOUDFLARE_ACCOUNT_ID_MODOL:-}" ] && {
  echo "REFUSING: target is the production account" >&2; exit 1; }

API="https://api.cloudflare.com/client/v4/accounts/${RORDI_TEST_CF_ACCOUNT}"
AUTH="Authorization: Bearer ${RORDI_TEST_CF_KEY}"
HERE="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

HELPER=${HELPER_NAME:-rordi-bridge-helper}
CONTROL=${CONTROL_NAME:-rordi-spike-control}

# Inputs the customer would type into Cloudflare's deploy-button form.
PAIRING_CODE="${PAIRING_CODE:?set PAIRING_CODE}"
BRIDGE_KEY="${BRIDGE_KEY:?set BRIDGE_KEY}"
SEED_SECRET="${SEED_SECRET:?set SEED_SECRET}"
WORKSPACE="${WORKSPACE_ID:-ws_spike_14142}"
CONTROL_URL="${CONTROL_URL:?set CONTROL_URL}"

upload() { # name metadata_file  (module parts appended by caller in $PARTS)
  local name="$1" meta="$2"; shift 2
  curl -sS -X PUT -H "$AUTH" \
    -F "metadata=@${meta};type=application/json" \
    "$@" \
    "${API}/workers/scripts/${name}"
}

# ── control plane (test-only Rordi stand-in) ────────────────────────────────
cat > "$TMP/cp-meta.json" <<JSON
{
  "main_module": "control-plane-worker.js",
  "compatibility_date": "2026-08-01",
  "bindings": [
    { "type": "secret_text", "name": "SEED_SECRET", "text": "${SEED_SECRET}" }
  ]
}
JSON
echo "── uploading ${CONTROL}"
upload "$CONTROL" "$TMP/cp-meta.json" \
  -F "control-plane-worker.js=@${HERE}/control-plane-worker.js;type=application/javascript+module" \
  -F "rordi-pair-endpoint.js=@${HERE}/../src/rordi-pair-endpoint.js;type=application/javascript+module" \
  -F "pairing.js=@${HERE}/../src/pairing.js;type=application/javascript+module" \
  | python3 -c 'import sys,json; d=json.load(sys.stdin); print("  ok" if d["success"] else json.dumps(d["errors"]))'

# ── helper Worker (what the customer deploys) ───────────────────────────────
cat > "$TMP/helper-meta.json" <<JSON
{
  "main_module": "worker.js",
  "compatibility_date": "2026-08-01",
  "bindings": [
    { "type": "plain_text",  "name": "RORDI_URL",          "text": "${CONTROL_URL}" },
    { "type": "plain_text",  "name": "RORDI_WORKSPACE",    "text": "${WORKSPACE}" },
    { "type": "secret_text", "name": "RORDI_PAIRING_CODE", "text": "${PAIRING_CODE}" },
    { "type": "secret_text", "name": "RORDI_BRIDGE_KEY",   "text": "${BRIDGE_KEY}" },
    { "type": "version_metadata", "name": "VERSION" }
  ]
}
JSON
echo "── uploading ${HELPER}"
upload "$HELPER" "$TMP/helper-meta.json" \
  -F "worker.js=@${HERE}/../src/worker.js;type=application/javascript+module" \
  -F "pairing.js=@${HERE}/../src/pairing.js;type=application/javascript+module" \
  | python3 -c 'import sys,json; d=json.load(sys.stdin); print("  ok" if d["success"] else json.dumps(d["errors"]))'

# ── enable workers.dev on both ──────────────────────────────────────────────
for w in "$CONTROL" "$HELPER"; do
  curl -sS -X POST -H "$AUTH" -H 'content-type: application/json' \
    "${API}/workers/scripts/${w}/subdomain" -d '{"enabled":true,"previews_enabled":false}' \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print('  subdomain ${w}:', 'ok' if d['success'] else d['errors'])"
done
