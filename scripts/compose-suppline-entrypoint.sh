#!/bin/sh
# Compose entrypoint: ensure demo signing keys exist, then start suppline.
set -eu

KEYS_DIR="${KEYS_DIR:-/keys/demo}"
PASSWORD="${ATTESTATION_KEY_PASSWORD:-demo}"

mkdir -p "$KEYS_DIR"

generate_keys() {
  echo "generating demo cosign keypair in $KEYS_DIR"
  rm -f "$KEYS_DIR/cosign.key" "$KEYS_DIR/cosign.pub"
  # Non-interactive when COSIGN_PASSWORD is set.
  (cd "$KEYS_DIR" && COSIGN_PASSWORD="$PASSWORD" cosign generate-key-pair)
}

if [ ! -f "$KEYS_DIR/cosign.key" ]; then
  generate_keys
elif ! COSIGN_PASSWORD="$PASSWORD" cosign public-key --key "$KEYS_DIR/cosign.key" >/dev/null 2>&1; then
  echo "existing cosign key not usable with demo password; regenerating"
  generate_keys
else
  echo "reusing existing cosign keypair in $KEYS_DIR"
fi

# Always load from the demo key file. Ignore any ATTESTATION_KEY from host .env
# so a production key is not paired with the demo password.
ATTESTATION_KEY="$(base64 -w0 "$KEYS_DIR/cosign.key")"
export ATTESTATION_KEY
export ATTESTATION_KEY_PASSWORD="$PASSWORD"
export COSIGN_PASSWORD="$PASSWORD"

exec /app/suppline
