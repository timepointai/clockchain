# Explorer template

A separate Fly app template for the static
[explorer](../../web/explorer/README.md): nginx serving the assembled
`web/explorer/dist/` tree. The page reads the public gateway (`/public/v1`)
from the browser; the app itself holds no key and reaches no node.

Nothing here runs from CI or a cloud session. Public exposure and every Fly
command are owner decisions and owner-run steps. The published URL, once there
is one, is recorded in [docs/PUBLIC-ACCESS.md](../../docs/PUBLIC-ACCESS.md).

| File | Purpose |
| --- | --- |
| `fly.toml` | App template: placeholder name, no IPs allocated, stops when idle |
| `Dockerfile` | Unprivileged nginx on 8080 serving `web/explorer/dist/`; build context is the repo root |
| `nginx.conf` | The server block: security headers, `application/wasm`, `/healthz` |

Copy `fly.toml` to a private location outside the checkout and replace
`<explorer-app>` there; the repository copy keeps the placeholder. The template
has no build section because `fly` resolves a `dockerfile` path relative to
the config file; pass `--dockerfile deploy/explorer/Dockerfile` from the repo
root. No secret is involved.

## Build

From the repo root. The page's API base and `connect-src` are fixed at build
time to the gateway origin, so the image is built for exactly one gateway:

```sh
cargo fetch --locked      # once, if the crates are not cached yet
web/explorer/build.sh --api-base https://timepoint-clockchain-gateway.fly.dev/public/v1
```

`build.sh` prints the sha256 of `cc_wasm_verify.wasm` and `taxonomy-v2.1.json`;
keep them with the deploy record. `dist/` is not committed; the root
`.dockerignore` re-includes it only so the image build can copy it.

## Enable (owner, from the workstation)

After review, from the repo root of a clean checkout of the reviewed commit,
with `dist/` assembled as above. `<explorer-app>` and `<org>` are placeholders.

```sh
fly apps create <explorer-app> --org <org>
fly deploy --config <private fly.toml> --dockerfile deploy/explorer/Dockerfile \
  --app <explorer-app> --no-public-ips --ha=false
# Record the image digest `fly machines list --json` reports.
fly ips list --app <explorer-app>      # must list nothing
fly status --app <explorer-app>
```

The commands that open public ingress, one per address family:

```sh
fly ips allocate-v6 --app <explorer-app>
fly ips allocate-v4 --shared --app <explorer-app>
```

## Verify

`<explorer-url>` is the app's `https://` origin.

```sh
curl -sI <explorer-url>/cc_wasm_verify.wasm | grep -i '^content-type'   # application/wasm
curl -sI <explorer-url>/healthz | head -1                                # 200
curl -sI <explorer-url>/index.html | grep -iE '^(x-frame-options|content-security-policy|strict-transport-security|cache-control)'
curl -s -o /dev/null -w '%{http_code}\n' <explorer-url>/missing          # 404
```

Run with `curl -4` and `curl -6` after an address change. Then open the page
and run "Verify in your browser" against the gateway.

## Trust

Hosting the page changes nothing about what it can vouch for. The explorer
does not authenticate the gateway or the origin of the corpus, and the
verifier it ships is only as independent as the build that produced it. Read
the trust-anchor paragraph in
[web/explorer/README.md](../../web/explorer/README.md#what-verify-in-your-browser-checks)
before pointing anyone at a published copy.

## Disable

The commands that remove public ingress immediately, one per address that
`fly ips list --app <explorer-app>` shows:

```sh
fly ips release <ipv6> --app <explorer-app>
fly ips release <ipv4> --app <explorer-app>
```

To stop serving as well: `fly scale count 0 --app <explorer-app>`. The gateway
is a separate app and is not affected; its own disable commands are in
[docs/PUBLIC-ACCESS.md](../../docs/PUBLIC-ACCESS.md).
