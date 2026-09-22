#!/usr/bin/env python3
"""Open or close the Railway Postgres TCP proxy, with a watchdog.

    ops/pg-proxy.py open [--minutes 20]
    ops/pg-proxy.py beat
    ops/pg-proxy.py close
    ops/pg-proxy.py status

The database is normally unreachable from the internet; that is the resting
state. This opens it for as long as a transfer needs and closes it again —
including when whatever opened it is killed outright.

A `trap` is not sufficient: SIGKILL does not run traps, and a foreground command
killed at a harness timeout once left this proxy open to the internet. So the
window is held by a HEARTBEAT file and closed by a detached watchdog as soon as
that file goes stale. Forgetting to close is no longer a way to stay exposed.

Env: CC_ENV_ID, CC_PG_SERVICE_ID, and RAILWAY_TOKEN (or ~/.railway/config.json).
"""
import json, os, pathlib, subprocess, sys, time, urllib.request

STATE = pathlib.Path(os.environ.get("TMPDIR", "/tmp")) / "cc-pgproxy"
STATE.mkdir(parents=True, exist_ok=True)
BEAT, HOSTF = STATE / "heartbeat", STATE / "host"


def gql(query, variables=None):
    tok = os.environ.get("RAILWAY_TOKEN") or json.load(
        open(os.path.expanduser("~/.railway/config.json")))["user"]["token"]
    req = urllib.request.Request(
        "https://backboard.railway.com/graphql/v2",
        data=json.dumps({"query": query, "variables": variables or {}}).encode(),
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + tok,
                 "User-Agent": "railway-cli/4.29.0"})   # Cloudflare 403s without one
    return json.loads(urllib.request.urlopen(req, timeout=60).read())


# Required for every subcommand, not just open: a close that fails because the
# env was not set leaves the database exposed, which is the failure this whole
# script exists to prevent.
ENV = os.environ.get("CC_ENV_ID") or sys.exit("set CC_ENV_ID")
SVC = os.environ.get("CC_PG_SERVICE_ID") or sys.exit("set CC_PG_SERVICE_ID")


def existing():
    return gql("""query($e:String!,$s:String!){ tcpProxies(environmentId:$e,serviceId:$s){ id proxyPort domain } }""",
               {"e": ENV, "s": SVC}).get("data", {}).get("tcpProxies", []) or []


def close():
    for p in existing():
        gql("""mutation($id:String!){ tcpProxyDelete(id:$id) }""", {"id": p["id"]})
    for f in (BEAT, HOSTF):
        f.unlink(missing_ok=True)
    return existing()


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "close":
        print("  proxies now:", close()); return
    if cmd == "status":
        print("  proxies:", existing(), "| heartbeat age:",
              int(time.time() - BEAT.stat().st_mtime) if BEAT.exists() else "none"); return
    if cmd == "beat":
        BEAT.touch(); print("  window extended"); return
    if cmd != "open":
        sys.exit("usage: pg-proxy.py open [--minutes N] | beat | close | status")

    mins = int(sys.argv[sys.argv.index("--minutes") + 1]) if "--minutes" in sys.argv else 20
    if not (ENV and SVC):
        sys.exit("set CC_ENV_ID and CC_PG_SERVICE_ID")
    BEAT.touch()
    d = gql("""mutation($in:TCPProxyCreateInput!){ tcpProxyCreate(input:$in){ domain proxyPort } }""",
            {"in": {"environmentId": ENV, "serviceId": SVC, "applicationPort": 5432}})["data"]["tcpProxyCreate"]
    host = f"{d['domain'].rstrip('.')}:{d['proxyPort']}"
    HOSTF.write_text(host)
    subprocess.Popen([sys.executable, __file__, "_watch", str(mins)],
                     start_new_session=True,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"  proxy open: {host}  (watchdog closes after {mins}m without a beat)")


if len(sys.argv) > 1 and sys.argv[1] == "_watch":
    limit = int(sys.argv[2]) * 60
    while True:
        time.sleep(20)
        if not BEAT.exists() or time.time() - BEAT.stat().st_mtime > limit:
            close(); break
else:
    main()
