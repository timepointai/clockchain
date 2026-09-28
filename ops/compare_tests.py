#!/usr/bin/env python3
"""Compare unittest discovery IDs in two checkouts without running their tests.

Use the interpreter/venv with each checkout's operator dependencies installed.
Each discovery runs in a separate process so module names cannot cross-contaminate.
A count difference is not necessarily a set of that many missing tests.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys

DISCOVER = '''import json, unittest
suite = unittest.defaultTestLoader.discover("ops", pattern="test_*.py")
def ids(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from ids(test)
        else:
            yield test.id()
found = sorted(ids(suite))
if any("_FailedTest" in name for name in found):
    raise RuntimeError("test discovery failed; inventory is incomplete: " + repr(found))
print(json.dumps(found))
'''


def discover(root):
    result = subprocess.run([sys.executable, '-c', DISCOVER], cwd=root,
                            text=True, capture_output=True, check=True)
    names = json.loads(result.stdout)
    if len(names) != len(set(names)):
        raise ValueError('duplicate test IDs; cannot compare as sets')
    return set(names)


def compare(left, right):
    a, b = discover(left), discover(right)
    return {
        'schema': 'cc.python-test-inventory.v1',
        'discovery_only': True,
        'left_count': len(a), 'right_count': len(b),
        'shared_count': len(a & b), 'net_difference': len(a) - len(b),
        'left_only': sorted(a - b), 'right_only': sorted(b - a),
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--left', type=Path, required=True)
    parser.add_argument('--right', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(compare(args.left.resolve(), args.right.resolve()), indent=2))
