#!/usr/bin/env bash
# Creates the credential encryption key that compose.yaml passes to the
# platform as AGENTFLOW_SECRET_KEY_FILE (connection secrets and bot
# credentials are sealed with it). Run by scripts/install.sh and
# ./start.sh pull; safe to re-run: an existing key is never replaced.
# Back the key up apart from database backups: without it encrypted
# credentials cannot be recovered.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -f .env ]]; then
  set -a; source .env; set +a
fi
: "${LOOPFORGE_DATA_DIR:?LOOPFORGE_DATA_DIR is not set; run scripts/configure.sh first}"
key_file="${AGENTFLOW_SECRET_KEY_FILE:-$LOOPFORGE_DATA_DIR/secrets/credentials.key}"
[[ -s "$key_file" ]] && exit 0
key_dir="$(dirname "$key_file")"
mkdir -p "$key_dir"
chmod 700 "$key_dir"
(
  umask 077
  python3 -c 'import base64,os; print(base64.b64encode(os.urandom(32)).decode())' > "$key_file.tmp"
  mv "$key_file.tmp" "$key_file"
)
printf 'Created the credential encryption key %s. Back it up separately from the database.\n' "$key_file"
