"""One way to reach the chain's database, supplied from outside.

    CC_DATABASE_URL=postgres://…  python3 ops/validate.py      # anyone

Four ops checks each carried their own copy of a `railway ssh | base64 | psql`
incantation, each hardcoded `clockchain_v4`, and three hardcoded one laptop's
home directory. That last one is not untidiness — **it makes those checks
unrunnable by anyone but one person on one machine**, which is fatal for a
tool whose entire purpose is letting a second party verify what the first party
claims. timepoint-telemetry can only read our output rather than run anything,
and this is why.

The ledger no longer lives on Railway. Resolution order, failing loudly:

  1. `CC_DATABASE_URL`  — a normal connection string, psql direct. The path an
     outside auditor uses, and the only one that survives a host move.
  2. refuse             — a checker that cannot reach the database must say so,
     not report a clean result over nothing.

A leftover `railway ssh` path remains behind `CC_USE_RAILWAY=1` so a dump from
the old host is still possible during cutover. It is not the default, and it
is not how telemetry is expected to run.

`CC_DATABASE_NAME` overrides the database, default `clockchain_v4`.
"""

import base64
import os
import shutil
import subprocess

SEP = "~|~"
DB = os.environ.get("CC_DATABASE_NAME", "clockchain_v4")
SERVICE = os.environ.get("CC_RAILWAY_SERVICE", "Postgres")


class Unreachable(RuntimeError):
    """The database could not be reached. Never swallowed into an empty result."""


CACHE = os.path.expanduser("~/.clockchain/railway-dir")


def _railway_dir():
    """A directory the railway CLI is linked from — discovered, then remembered.

    The cache exists because the alternative failed five times in one session:
    the linked project is a SIBLING of this repo, so discovery from `cwd` or from
    this file's repo finds nothing, and every run from the wrong directory looked
    like the module breaking rather than the caller standing in the wrong place.

    It is machine-local state in `~/.clockchain/`, never a literal in the repo —
    which is the distinction that matters for open-sourcing. Absent by default,
    written only after a successful probe, and re-probed if it goes stale.
    """
    candidates = [os.environ.get("CC_RAILWAY_DIR")]
    try:
        with open(CACHE) as fh:
            candidates.append(fh.read().strip())
    except OSError:
        pass
    candidates += [os.getcwd(),
                   os.path.dirname(os.path.dirname(os.path.abspath(__file__)))]
    for d in candidates:
        if not d or not os.path.isdir(d):
            continue
        r = subprocess.run(["railway", "status"], capture_output=True, text=True, cwd=d)
        if r.returncode == 0:
            try:
                os.makedirs(os.path.dirname(CACHE), exist_ok=True)
                with open(CACHE, "w") as fh:
                    fh.write(d)
            except OSError:
                pass
            return d
    return None


def describe():
    """Which path is in use, so a report can state how it reached the data."""
    if os.environ.get("CC_DATABASE_URL"):
        return f"direct psql to {DB} (CC_DATABASE_URL)"
    if os.environ.get("CC_USE_RAILWAY") == "1":
        return "UNREACHABLE: Railway transport is retired"
    return "UNREACHABLE"


def run(sql, timeout=300):
    """Execute `sql`, return raw stdout. Base64 because the SQL crosses shells."""
    url = os.environ.get("CC_DATABASE_URL")
    if url:
        r = subprocess.run(["psql", url, "-At", "-F", SEP, "-v", "ON_ERROR_STOP=1", "-c", sql],
                           capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0:
            raise Unreachable((r.stderr.strip() or r.stdout.strip())[:600])
        return r.stdout

    if os.environ.get("CC_USE_RAILWAY") == "1":
        raise Unreachable("Railway transport is retired; set CC_DATABASE_URL")
    if os.environ.get("CC_USE_RAILWAY") != "1":
        raise Unreachable(
            "no CC_DATABASE_URL — set it to a connection string. "
            "Legacy Railway transport is retired.")
    if not shutil.which("railway"):
        raise Unreachable(
            "CC_USE_RAILWAY=1 but no railway CLI — set CC_DATABASE_URL instead")
    d = _railway_dir()
    if not d:
        raise Unreachable(
            "CC_USE_RAILWAY=1 but no directory here is linked to a railway project. "
            "Set CC_DATABASE_URL.")
    b64 = base64.b64encode(sql.encode()).decode()
    cmd = (f"echo {b64} | base64 -d > /tmp/ccdb.sql && "
           f"PAGER=cat psql -U postgres -d {DB} -At -F '{SEP}' -f /tmp/ccdb.sql")
    r = subprocess.run(["railway", "ssh", "--service", SERVICE, cmd],
                       capture_output=True, text=True, timeout=timeout, cwd=d)
    if r.returncode != 0:
        raise Unreachable((r.stderr.strip() or r.stdout.strip())[:600])
    return r.stdout


def rows(sql, timeout=300):
    """`sql` as a list of field-lists. Empty result and failure are different:
    failure raises, so a check can never mistake one for the other."""
    return [l.split(SEP) for l in run(sql, timeout).splitlines() if l.strip()]


def scalar(sql, timeout=300):
    r = rows(sql, timeout)
    return r[0][0] if r and r[0] else None
