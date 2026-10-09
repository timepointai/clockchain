# Public gateway template

A separate Fly app template for `cc-gateway`, the unauthenticated, read-only
`/public/v1` API in front of the private v1 node.

Nothing here runs from CI or a cloud session. Public exposure, the read-key
choice and every Fly command are owner decisions and owner-run steps; see
[docs/PUBLIC-ACCESS.md](../../docs/PUBLIC-ACCESS.md), whose Status section
records whether a gateway is currently enabled.

| File | Purpose |
| --- | --- |
| `fly.toml` | App template: placeholder names, Flycast node URL, no IPs allocated |
| `Dockerfile` | Multi-stage build of `cc-gateway` only; build context is the repo root |

Copy `fly.toml` to a private location outside the checkout and replace
`<public-app>` and `<node-app>` there; the repository copy keeps placeholders.
The template has no build section because `fly` resolves a `dockerfile` path
relative to the config file; pass `--dockerfile deploy/public/Dockerfile` from
the repo root. The read key is a Fly secret (`CC_GATEWAY_READ_KEY`) and never
appears in these files.
