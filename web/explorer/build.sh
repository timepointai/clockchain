#!/usr/bin/env bash
# Assemble the static explorer into web/explorer/dist. Local only: it runs
# cargo against the workspace (no network beyond what cargo already cached)
# and copies files. The page loads nothing from any CDN.
#
#   web/explorer/build.sh [--api-base URL] [--fixture]
#
# --api-base  where /public/v1 lives; default same-origin "/public/v1". A URL on
#             another origin is also added to the page's connect-src.
# --fixture   include the recorded synthetic fixture (open with ?fixture=synthetic).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
api_base="/public/v1"
fixture=0
while [ $# -gt 0 ]; do
  case "$1" in
    --api-base) api_base="$2"; shift 2 ;;
    --fixture) fixture=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
case "$api_base" in
  /*) connect="'self'" ;;
  https://*) origin="$(printf '%s' "$api_base" | sed -E 's#^(https://[^/]+).*#\1#')"; connect="'self' $origin" ;;
  *) echo "--api-base must be a path or an https URL" >&2; exit 2 ;;
esac
case "$api_base" in *[\"\<\>\'\ ]*) echo "--api-base contains a forbidden character" >&2; exit 2 ;; esac

cargo build --manifest-path "$root/Cargo.toml" -p cc-wasm-verify \
  --target wasm32-unknown-unknown --release
dist="$here/dist"
rm -rf "$dist"
mkdir -p "$dist/js"
cp "$here/style.css" "$dist/"
cp "$here"/js/*.js "$dist/js/"
cp "$root/target/wasm32-unknown-unknown/release/cc_wasm_verify.wasm" "$dist/"
cp "$root/vendor/tt/taxonomy-v2.1.json" "$dist/"
sed -e "s#connect-src 'self'#connect-src $connect#" \
    -e "s#name=\"cc-api-base\" content=\"/public/v1\"#name=\"cc-api-base\" content=\"$api_base\"#" \
    "$here/index.html" > "$dist/index.html"
if [ "$fixture" = 1 ]; then
  mkdir -p "$dist/fixtures"
  cp -R "$here/fixtures/synthetic" "$dist/fixtures/"
fi
( cd "$dist" && sha256sum cc_wasm_verify.wasm taxonomy-v2.1.json )
echo "explorer assembled in $dist"
