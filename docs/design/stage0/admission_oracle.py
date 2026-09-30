"""Stdlib-only differential adapter. The accepted Stage 0 fold is unchanged.

Stage (a) compares branch-local G/C admission, not head/frontier projection.
Stages (b)/(c) must expand the input domain and compare the full View.
"""
import json
import sys
from model import Event, fold


def classify(case):
    events = [Event(**dict(e, parents=tuple(e.get("parents", ())))) for e in case]
    return [[i, s if s in ("invalid", "pending") else "valid",
             reason if s in ("invalid", "pending") else ""]
            for i, s, reason in fold(events).rows]


if __name__ == "__main__":
    print(json.dumps([classify(case) for case in json.load(sys.stdin)]))
