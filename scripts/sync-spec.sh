#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --source <path-to-pact-ref-spec>" >&2
  echo "       $0 --source <path> --check" >&2
}

source_dir=""
check=0
while [ $# -gt 0 ]; do
  case "$1" in
    --source) source_dir="${2:-}"; shift 2 ;;
    --check) check=1; shift ;;
    *) usage; exit 2 ;;
  esac
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target_dir="$repo_root/vendor/pact-ref-spec"

if [ -z "$source_dir" ] || [ ! -f "$source_dir/Cargo.toml" ]; then
  usage
  exit 2
fi

if [ "$check" -eq 1 ]; then
  if diff -r --exclude target --exclude Cargo.lock "$source_dir" "$target_dir" >/dev/null; then
    echo "vendored spec is in sync"
    exit 0
  fi
  echo "vendored spec is out of sync; rerun without --check" >&2
  exit 1
fi

rm -rf "$target_dir"
mkdir -p "$target_dir"
tar -C "$source_dir" --exclude target --exclude Cargo.lock -cf - . \
  | tar -C "$target_dir" -xf -

content_sha256="$(
  cd "$target_dir"
  find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}'
)"

cat > "$repo_root/vendor/pact-ref-spec-source.json" <<JSON
{
  "name": "pact-ref-spec",
  "version": "0.1.0",
  "contentSha256": "$content_sha256"
}
JSON

echo "synced spec into $target_dir"
