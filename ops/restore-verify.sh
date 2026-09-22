#!/usr/bin/env bash
# M6 restore-verify: prove a backup is restorable and that the restored database
# is still a Clockchain node rather than a pile of rows shaped like one.
#
# A backup that restores is not the same as a backup that restores CORRECTLY.
# The failures this drill exists to catch are the quiet ones:
#
#   * a client/server major mismatch, which makes `pg_dump` refuse outright —
#     the backup does not silently degrade, it silently never happens;
#   * a restore that loses the append-only trigger, leaving a database that
#     accepts history edits and looks fine;
#   * a restore that loses the exhibit immutability triggers, so the founding
#     corpus becomes editable;
#   * a count checked against `ledger_stats`, which is a mutable projection and
#     therefore agrees with itself even when it is wrong.
#
# Usage:  ops/restore-verify.sh <SOURCE_DATABASE_URL> [SCRATCH_DB_NAME]
#
# The scratch database is created and left in place for inspection. Nothing in
# this script writes to the source.

set -euo pipefail

SRC="${1:?usage: restore-verify.sh <SOURCE_DATABASE_URL> [SCRATCH_DB_NAME]}"
SCRATCH="${2:-clockchain_restore_check}"

# ---------------------------------------------------------------------------
# 0. The client-major gate, first, because everything below is meaningless if
#    the dump never happened.
# ---------------------------------------------------------------------------
#
# Homebrew keeps versioned clients unlinked, so the `pg_dump` on PATH is
# whichever one was linked last — routinely an old one. A major-version-older
# client does not produce a degraded dump; it refuses, and a backup cron that
# does not check its exit status records success for a file it never wrote.

server_major() {
    psql "$SRC" -tAc 'SHOW server_version' | cut -d. -f1
}

find_pg_bin() {
    local want="$1" name="$2"
    for candidate in \
        "/opt/homebrew/opt/postgresql@${want}/bin/${name}" \
        "/usr/local/opt/postgresql@${want}/bin/${name}" \
        "/usr/lib/postgresql/${want}/bin/${name}"; do
        [[ -x "$candidate" ]] && { echo "$candidate"; return 0; }
    done
    # Fall back to PATH only if it happens to be the right major.
    if command -v "$name" >/dev/null 2>&1; then
        local have
        have="$("$name" --version | grep -oE '[0-9]+' | head -1)"
        [[ "$have" == "$want" ]] && { command -v "$name"; return 0; }
    fi
    return 1
}

SERVER_MAJOR="$(server_major)"
echo "server major ......... $SERVER_MAJOR"

PG_DUMP="$(find_pg_bin "$SERVER_MAJOR" pg_dump)" || {
    echo "FAIL: no pg_dump with major $SERVER_MAJOR found." >&2
    echo "      PATH has: $(pg_dump --version 2>/dev/null || echo none)" >&2
    echo "      On macOS: brew install postgresql@${SERVER_MAJOR}" >&2
    exit 1
}
PSQL="$(find_pg_bin "$SERVER_MAJOR" psql)" || PSQL="psql"
echo "pg_dump .............. $($PG_DUMP --version)"

# ---------------------------------------------------------------------------
# 1. Dump and restore.
# ---------------------------------------------------------------------------

ADMIN="${SRC%/*}/postgres"
DEST="${SRC%/*}/${SCRATCH}"
# `CC_KEEP_DUMP=<path>` retains the artifact instead of discarding it, so the
# same run that PROVES a dump restores also produces the file you archive. A
# backup verified by one dump and shipped as a different one is not verified.
if [[ -n "${CC_KEEP_DUMP:-}" ]]; then
    DUMP="$CC_KEEP_DUMP"
else
    DUMP="$(mktemp -t clockchain-restore-verify).sql"
    trap 'rm -f "$DUMP"' EXIT
fi

echo "dumping to ........... $DUMP"
"$PG_DUMP" --no-owner --no-privileges "$SRC" > "$DUMP"
echo "dump size ............ $(wc -c < "$DUMP") bytes"

"$PSQL" "$ADMIN" -qc "DROP DATABASE IF EXISTS ${SCRATCH}"
"$PSQL" "$ADMIN" -qc "CREATE DATABASE ${SCRATCH}"
"$PSQL" -q "$DEST" < "$DUMP" > /dev/null
echo "restored into ........ $SCRATCH"

fail() { echo "FAIL: $*" >&2; exit 1; }
q() { "$PSQL" -tA "$DEST" -c "$1"; }

# ---------------------------------------------------------------------------
# 2. Event count — against the ledger, NOT against ledger_stats.
# ---------------------------------------------------------------------------
#
# `ledger_stats` is a mutable projection. Verifying a restore against it asks
# the copy to agree with itself. The source `events` count is the fact; where a
# root has been published, `roots.tree_size` of the latest one is a stronger
# fact still, because it is committed to by a signed moment and (once anchored)
# by Bitcoin.

SRC_EVENTS="$(psql -tA "$SRC" -c 'SELECT count(*) FROM events')"
DST_EVENTS="$(q 'SELECT count(*) FROM events')"
[[ "$SRC_EVENTS" == "$DST_EVENTS" ]] || fail "events $SRC_EVENTS != $DST_EVENTS"
echo "events ............... $DST_EVENTS (matches source)"

LEAVES="$(q "SELECT coalesce(max(tree_size)::text,'') FROM roots")"
if [[ -n "$LEAVES" ]]; then
    [[ "$LEAVES" -le "$DST_EVENTS" ]] \
        || fail "latest root commits to $LEAVES leaves but only $DST_EVENTS events restored"
    echo "anchored leaves ...... $LEAVES (<= restored events)"
else
    echo "anchored leaves ...... none published yet (nothing to check against)"
fi

UNSIGNED="$(q 'SELECT count(*) FROM events WHERE signature IS NULL')"
[[ "$UNSIGNED" == "0" ]] || fail "$UNSIGNED restored events carry no signature"
echo "unsigned events ...... 0"

DANGLING="$(q 'SELECT count(*) FROM events e LEFT JOIN exhibits x ON x.exhibit_id = e.provenance_exhibit
               WHERE e.provenance_exhibit IS NOT NULL AND x.exhibit_id IS NULL')"
[[ "$DANGLING" == "0" ]] || fail "$DANGLING provenance pointers resolve to nothing"
echo "dangling provenance .. 0"

# ---------------------------------------------------------------------------
# 3. The guards must have survived the round trip.
# ---------------------------------------------------------------------------
#
# Each of these asserts a WRITE FAILS. A restore that drops a trigger produces a
# database that passes every read-shaped check and quietly permits history
# edits, which is the single worst outcome this drill can miss.

refuses() {
    local what="$1" sql="$2"
    if "$PSQL" -q "$DEST" -c "$sql" >/dev/null 2>&1; then
        fail "$what was PERMITTED — the guard did not survive the restore"
    fi
    echo "$what ... correctly refused"
}

refuses "events UPDATE      " \
    "UPDATE events SET payload = payload WHERE event_id = (SELECT event_id FROM events LIMIT 1)"
refuses "events DELETE      " \
    "DELETE FROM events WHERE event_id = (SELECT event_id FROM events LIMIT 1)"
refuses "exhibit UPDATE     " \
    "UPDATE exhibits SET byte_len = byte_len + 1"
refuses "exhibit DELETE     " \
    "DELETE FROM exhibits"

# ---------------------------------------------------------------------------
# 4. The restored view must be re-derivable from the restored events.
# ---------------------------------------------------------------------------
#
# Left to the caller, because it needs the workspace: `cc-migrator mirror
# --from <restored>` replays into a third database and compares `view_root`. A
# restore can be byte-perfect and still hold a projection that no longer follows
# from its own events.

echo
echo "PASS: $SCRATCH restored, counted, and still refuses to be rewritten."
echo "next: DATABASE_URL=<fresh> cargo run -p cc-migrator -- mirror --from '$DEST'"
