#!/usr/bin/env bash
# Owner-operated release. GitHub CI never deploys or holds production credentials.
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 ops/release.py "$@"
