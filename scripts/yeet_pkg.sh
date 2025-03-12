#!/usr/bin/env bash

set -euo pipefail

exit_success=0
exit_failure=1

mode="pkg"
target=${TARGET:-}

usage() {
  >&2 cat <<EOF
Usage:
  yeet_pkg.sh [OPTIONS]

Options:
  -u          Unpackage
  --target    Target directory to package / unpackage
EOF
}


while [[ $# -gt 0 ]]; do
  case "$1" in
    -u)
      mode="unpkg"
      shift 1
      ;;
    --target)
      target=$2
      shift 2
      ;;
    --help)
      usage
      exit $exit_success
      ;;
    *)
      usage
      exit $exit_failure
      ;;
  esac
done


if [ -z "$target" ]; then
  >&2 echo "Error: Target not specified. Use --target to specify a target."
  usage
  exit $exit_failure
fi


if [ "$mode" = "pkg" ]; then
  mkdir -p "$target"
  mkdir -p "$target/bin"
  cp "bin/$target" "$target/bin/$target"
  cp YEET "$target/YEET"
  tar -cf "$target.tar" "$target"
  zstd -f --ultra -22 "$target.tar" -o "$target.yeet"
  rm -rf "$target"
  rm -rf "$target.tar"
elif [ "$mode" = "unpkg" ]; then
  zstd -d --ultra -22 "$target.yeet" -o "$target.tar"
  tar -xf "$target.tar"
  rm -rf "$target.tar"
  rm -rf "$target.yeet"
else
  >&2 echo "Error: Invalid mode. Use -u for unpacking or omit for packaging."
  usage
  exit $exit_failure
fi