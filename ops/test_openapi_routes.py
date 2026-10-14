"""docs/reference/openapi.json must list exactly the routes the routers mount.

Reads the axum router source rather than running a server: every
`.route("<path>", <method>(...))` in the cc-gateway router and the cc-node v1
`router_with` is compared with the spec's paths and methods, so adding,
removing or renaming a route without updating the spec fails here.
"""

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "docs" / "reference" / "openapi.json"
GATEWAY = ROOT / "crates" / "cc-gateway" / "src" / "lib.rs"
NODE = ROOT / "crates" / "cc-node" / "src" / "serve_v1.rs"

ROUTE = re.compile(r'\.route\(\s*"([^"]+)",\s*(?:if live \{\s*)?(get|post|put|delete|patch)\(', re.S)


def mounted(source: Path, start: str) -> set[tuple[str, str]]:
    text = source.read_text()
    body = text[text.index(start):]
    body = body[: body.index("\n}\n")]
    return {
        (method, re.sub(r":(\w+)", r"{\1}", path))
        for path, method in ROUTE.findall(body)
    }


def documented(tag: str) -> set[tuple[str, str]]:
    spec = json.loads(SPEC.read_text())
    return {
        (method, path)
        for path, item in spec["paths"].items()
        for method, op in item.items()
        if tag in op.get("tags", [])
    }


class OpenApiMatchesRouters(unittest.TestCase):
    def test_gateway(self):
        routes = mounted(GATEWAY, "pub fn router(")
        self.assertEqual(len(routes), 6)
        self.assertEqual(routes, documented("public"))

    def test_node_v1(self):
        routes = mounted(NODE, "pub fn router_with(")
        self.assertEqual(len(routes), 12)
        self.assertEqual(routes, documented("node"))


if __name__ == "__main__":
    unittest.main()
