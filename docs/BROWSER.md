# Clockchain browser

One read-only localhost browser displays validated local candidates and records
from local or deployed Clockchain nodes, including original PNGs and provenance.
It uses node HTTP read APIs; no database or signing credential is needed.
Older versioned viewers and the separate proposal/image preview servers are retired.

Store configuration outside the checkout, with owner-only read credentials:

```json
{
  "schema": "cc.browser.v1",
  "port": 8766,
  "default_source": "draft",
  "sources": [
    {"id": "draft", "label": "Local candidate", "kind": "local", "attempt": "/private/attempt"},
    {"id": "deployed", "label": "Deployed Clockchain", "kind": "node",
     "url": "http://127.0.0.1:18080", "read_key_file": "/private/node-read.key"}
  ]
}
```

Run in the foreground on any supported Python platform:

```sh
python3 ops/browse.py --config /private/browser.json --open
```

On macOS, install the same application as a durable login service:

```sh
python3 ops/browser_service.py install --config /private/browser.json
python3 ops/browser_service.py open
python3 ops/browser_service.py status
python3 ops/browser_service.py restart
python3 ops/browser_service.py stop
```

Installation registers `com.clockchain.browser` with launchd, starts immediately,
and restarts after failure and on login. Re-run install after changing the Python
runtime or configuration path. Use restart after editing source definitions.
Stop unloads the job for the current login; uninstall also removes its plist.
The service uses the Python interpreter that runs the installer. Logs remain
beside the private configuration. The service does not open a browser tab on login.

For a private Fly deployment, the configuration can also own its access tunnel:

```json
"fly_tunnel": {
  "executable": "/absolute/path/to/flyctl",
  "app": "your-private-app",
  "port": 18080
}
```

The browser supervises a loopback Flycast proxy using the owner's existing Fly
login. The proxy is a transport for the configured node; it does not deploy or
change the node. Without this option, arrange the node connection separately.
HTTPS origins are supported directly. HTTP origins must be loopback.

## Local and deployed records

A local source points to one application attempt with `proposal.json` and
`result.json`. Image-prepared attempts also require their matching application
admission receipt. Every refresh verifies the candidate digest and each image's
digest; images must resolve inside the attempt directory. Historical fields are
displayed unchanged. Prepared media remains visibly pending review. Add another
source or change the configured attempt to inspect another run.

A node source reads up to 50 latest moments at an explicit coordinate, then their
entities and recorded directed relationships. The coordinate defaults to the
current whole-second Gregorian offset from the Clockchain epoch and is shown
in the form. Enter an exact decimal entity ID for records outside that window.
This bounded view is not a complete corpus export; moments can share coordinates.
API fields are shown as returned. Updated nodes expose the exact stored claim
body for each reading; missing bodies and older endpoints display an explicit
prose-unavailable message. The browser never reconstructs prose from local files.

Select a node to read its `/v2/media` readings, including stale body bindings,
absence decisions and conflicts. Image requests recheck membership in that
entity's media at the same coordinate and verify the returned PNG hash. Failed
media reads stay errors; they are never labeled deliberately unillustrated.
An empty deployment is shown as empty. Nothing is populated or published to make
the browser appear functional.
Claims alone create no media readings. Updated nodes return `readings: []` when
there are no admitted media records. The browser can still display an older
node's explicit `no_generation_recorded` response without turning it into absence.

Credentials stay server-side. The browser refuses credential-bearing redirects,
unexpected Host headers, cross-site browser requests, and arbitrary file paths.
It serves only its UI and verified images, with no-store and a restrictive CSP.
All form actions are reads. Publication and media admission remain owner-operated.
Use the [owner-only publication checklist](PUBLICATION-GATE.md) privately before
preparing a candidate for publication.

## Empty and failed reads

Check these paths without adding records to the node:

| Request | Expected distinction |
|---|---|
| Empty node, no entity ID | Successful empty coordinate window, no inferred media decision |
| Malformed or unknown entity ID | Read error, no empty-corpus result |
| Older valid `as_of` | Read that coordinate; an empty window says nothing about current coverage |
| Malformed `as_of` | Read error, no fallback to the current coordinate |
| Hash absent from the entity's media at `as_of` | Image request refused before fetching PNG bytes |
| Failed media API or failed PNG integrity | Error; never deliberate non-illustration |

An old coordinate is not inherently invalid or expired. Media responses describe
their projection basis and preserve stale body bindings; they do not reconstruct
a past projection. On an empty production corpus, cross-entity and stale-reading
isolation must also be tested with isolated synthetic fixtures, never by seeding
production. Regression coverage lives in `ops/test_browser.py` and the node's
real-Postgres media tests.
