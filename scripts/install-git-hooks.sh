#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOOKS_DIR="$ROOT_DIR/.git/hooks"

if [[ ! -d "$HOOKS_DIR" ]]; then
  echo "Error: .git/hooks directory not found. Run from a git repository clone." >&2
  exit 1
fi

cat > "$HOOKS_DIR/pre-push" <<'HOOK'
#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
"$ROOT_DIR/scripts/pre-push-check.sh"
HOOK

chmod +x "$HOOKS_DIR/pre-push"
chmod +x "$ROOT_DIR/scripts/pre-push-check.sh"

echo "Installed pre-push hook at $HOOKS_DIR/pre-push"
