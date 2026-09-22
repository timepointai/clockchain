#!/usr/bin/env python3
"""Read-only assertion: every image body is projected by some moment.

Exit 0: PASS (including an explicitly empty catalog); 1: orphan found;
2: NOT RUN. Supply CC_DATABASE_URL; no production repair is attempted.
"""
import json
import os
from pathlib import Path
import sys

import ccdb

SQL = Path(__file__).resolve().parents[1] / "crates/cc-node/sql/media-integrity.sql"


def main():
    if not os.environ.get("CC_DATABASE_URL"):
        print("NOT RUN: set CC_DATABASE_URL to run the media assertion")
        return 2
    try:
        report = json.loads(ccdb.run(SQL.read_text()))
        print(json.dumps(report, indent=2))
        return 0 if report["integrity"] == "pass" else 1
    except Exception:
        # Connection errors may contain credentials; do not echo them.
        print("NOT RUN: could not read the media integrity report", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
