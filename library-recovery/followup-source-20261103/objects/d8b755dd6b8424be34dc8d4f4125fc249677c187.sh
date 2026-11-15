#!/usr/bin/env bash
# Exact-head, non-deploying Rust qualification for Hepta Runtime.
# This script does NOT establish target-host final-use or production acceptance.
set -Eeuo pipefail

if [[ $# -ne 1 ]]; then
  printf 'Usage: %s /absolute/path/to/hepta-runtime-worktree\n' "$0" >&2
  exit 64
fi

REPO=$1
EXPECTED_SHA=${HEPTA_EXPECTED_SHA:-f1ae4b5f84740272a9c803aa09ba548bf4b1263d}
if ! [[ -d "$REPO/.git" || -f "$REPO/.git" ]]; then
  printf 'BLOCKED: no Git worktree at %s\n' "$REPO" >&2
  exit 66
fi
if ! command -v rustc >/dev/null || ! command -v cargo >/dev/null || ! command -v rustfmt >/dev/null || ! command -v cargo-clippy >/dev/null; then
  printf 'BLOCKED: rustc, cargo, rustfmt and cargo-clippy must be present\n' >&2
  exit 69
fi
ACTUAL_SHA=$(git -C "$REPO" rev-parse HEAD)
if [[ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]]; then
  printf 'BLOCKED: exact-head mismatch. expected=%s actual=%s\n' "$EXPECTED_SHA" "$ACTUAL_SHA" >&2
  exit 70
fi
if [[ -n $(git -C "$REPO" status --porcelain) ]]; then
  printf 'BLOCKED: worktree is not clean; do not qualify an uncommitted candidate\n' >&2
  exit 71
fi

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
ROOT=${HEPTA_EVIDENCE_ROOT:-"$HOME/hepta-qualification"}
DEST="$ROOT/$STAMP-${ACTUAL_SHA:0:12}"
mkdir -p "$DEST"
{
  printf 'source_sha=%s\n' "$ACTUAL_SHA"
  printf 'commit_tree=%s\n' "$(git -C "$REPO" rev-parse HEAD^{tree})"
  printf 'execution_utc=%s\n' "$STAMP"
  printf 'hostname=%s\n' "$(hostname)"
  printf 'platform=%s\n' "$(uname -srm)"
  printf 'rustc=%s\n' "$(rustc --version)"
  printf 'cargo=%s\n' "$(cargo --version)"
  printf 'rustfmt=%s\n' "$(rustfmt --version)"
  printf 'status=IN_PROGRESS\n'
} > "$DEST/manifest.txt"

run_gate() {
  local name=$1
  shift
  printf 'Running %s on exact SHA %s\n' "$name" "$ACTUAL_SHA"
  if (cd "$REPO" && "$@") >"$DEST/$name.log" 2>&1; then
    printf '%s=PASS\n' "$name" >>"$DEST/manifest.txt"
  else
    rc=$?
    printf '%s=FAIL:%s\n' "$name" "$rc" >>"$DEST/manifest.txt"
    printf 'BLOCKED: %s failed (exit %s), see %s/%s.log\n' "$name" "$rc" "$DEST" "$name" >&2
    exit "$rc"
  fi
}

run_gate format cargo fmt --all -- --check
run_gate check cargo check --locked --all-targets
run_gate clippy cargo clippy --locked --all-targets -- -D warnings
run_gate test cargo test --locked --all-targets
run_gate release cargo build --locked --release
sed -i 's/^status=IN_PROGRESS$/status=RUST_SOURCE_GATES_PASS_ONLY/' "$DEST/manifest.txt"
(cd "$DEST" && sha256sum ./*.log manifest.txt > SHA256SUMS)
printf '\nRust source gates passed for exact commit %s\nEvidence: %s\n' "$ACTUAL_SHA" "$DEST"
printf 'NOT PROVEN: remote-host effects, privilege Final-use, independent acceptance, canary, release.\n'
