# Publisher v1

`cc-publisher v1` signs a v1 Genesis offline, submits it to a node running in
v1 mode, and reads it back. The contract is in the "Publisher CLI" and "HTTP in
v1 mode" sections of [STAGE-F.md](design/STAGE-F.md). This page describes what
the code does.

## Scope

- `keygen`, `pubkey` and `genesis` work offline. `node-info`, `submit` and
  `verify` talk to a node over HTTP and nothing else.
- No `v1` command opens a database or reads `DATABASE_URL`. The envelope is
  built with the `cc_core::v1` types the node itself decodes.
- Only Genesis events are built.
- The v0 commands (`validate`, `publish` and the rest) are unchanged.

Common rules:

- Hex arguments (`--instance`, `--evidence`, `--nonce`, `--subject`) are
  exactly 64 hex characters, either case. Printed hex is lowercase.
- Exit status is 0 on success and 1 on any refusal or failure. The error goes
  to stderr as `cc-publisher v1: ` followed by its causes, joined by `: `.
  Argument errors found by the parser, such as a missing flag, exit 2.
- `cc-publisher v1 <command> --help` lists the flags.

## Security model

### Secrets

The signing seed is read only from the `--key` file. Node tokens are read only
from the environment. No flag takes a secret.

| Command | Token |
|---|---|
| `submit` | `CC_NODE_API_KEY` (write) |
| `verify` | `CC_NODE_READ_KEY`; `CC_NODE_API_KEY` only when `CC_NODE_READ_KEY` is unset |
| `node-info` | None; `/health` is public |

A variable that is set but blank is refused; it does not fall back. The token
is sent as `Authorization: Bearer <token>` exactly as set, so it must not
contain a newline or other control character. `submit` also sends
`CC_NODE_API_KEY` on its read-back requests. The tool never prints a token or a
seed, and an error about a malformed key file does not quote the file.

### Key files

A key file holds a 32-byte Ed25519 seed (RFC 8032) as exactly 64 hex
characters, either case, and an optional final newline. Nothing else is
accepted: no spaces, no carriage return. `keygen` writes 64 lowercase hex
characters and a newline. The seed is not encrypted; protect the file and any
copy of it.

`keygen` never replaces a file and never exposes a partial one:

1. It refuses if the target exists, a dangling symlink included.
2. It writes the seed to a new file `.<name>.<16 hex>.tmp` in the target's
   directory, created exclusively and set to exactly mode 0600 whatever the
   umask, and syncs it.
3. It hard-links that file to the target. The link fails if the target
   appeared meanwhile, so the target is never overwritten and never appears
   partially written.
4. It removes the temporary file, syncs the directory, and reads the key back
   through the loader `genesis` uses.

The target's directory must exist and its filesystem must support hard links.
If `keygen` is interrupted, the temporary file, which holds a seed, may remain
beside the target. Delete it.

Loading (`pubkey`, `genesis`) opens the file and checks the open handle before
reading it. It must be a regular file (a symlink is followed). Its mode must
have none of setuid, setgid, sticky, owner execute, or any group or other bit
(mask `07177`). Modes 0600 and 0400 pass; 0640, 0644 and 0700 are refused.

### Node URL and transport

`--node` is the node's absolute base URL.

- `https://` is accepted for any host.
- `http://` is accepted only for loopback IP literals (`127.0.0.0/8`,
  `[::1]`), `localhost`, and single-label host names without a dot, such as a
  container name on a private Docker network. Any dotted name and any other IP
  literal needs `https://`. The rule exists so a bearer token never crosses the
  public internet in clear text.
- Other schemes, user info (`user:pass@`), a query and a fragment are refused.
- A path is kept as a prefix: `https://node.example/cc` sends
  `https://node.example/cc/health`.
- Redirects are never followed. A 3xx is an error, so a token is never
  replayed to another URL.
- The connect timeout is 15 s and each request times out after 120 s. A
  response over 16 MiB is refused.
- TLS uses rustls with the bundled Mozilla root set (webpki-roots). The
  operating-system trust store is not used, so a private-CA certificate fails.
- The client honors `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY` and `NO_PROXY`.
  For plain http, unset `HTTP_PROXY` and `ALL_PROXY` or list the host in
  `NO_PROXY`; otherwise the request, token included, goes to the proxy in
  clear text.
- A single-label name goes through the system resolver, where a DNS search
  domain can turn it into a remote name. Use plain http only where the name
  stays on the private network.

## Typical sequence

Placeholders are in capitals. `entry/` must not exist yet, or be empty.

```sh
# 1. Offline: create the curator key. Prints the public key.
cc-publisher v1 keygen --out curator.seed
# 2. Offline: print the public key again.
cc-publisher v1 pubkey --key curator.seed
# 3. Read the node's identity. Confirm ledger, posture, semantic, instance,
#    that curators lists the public key, and the two consistency flags.
cc-publisher v1 node-info --node https://node.example
# 4. Offline: sign into a new directory.
cc-publisher v1 genesis --key curator.seed --instance INSTANCE_HEX \
  --kind TT_NODE_ID --namespace NAMESPACE --value VALUE \
  --body body.txt --asserted-time YYYY-MM-DD \
  --evidence EVIDENCE_SHA256 --out entry/
# 5. Review entry/body.bin and entry/preview.json.
# 6. Submit. The write token comes from the environment.
CC_NODE_API_KEY=... cc-publisher v1 submit --node https://node.example --dir entry/
# 7. Verify. SUBJECT_HEX is "subject" in entry/preview.json.
CC_NODE_READ_KEY=... cc-publisher v1 verify --node https://node.example \
  --subject SUBJECT_HEX --dir entry/
```

A real token typed into a command line is saved in shell history. Read it into
the environment instead, and unset it when done:

```sh
read -rs CC_NODE_API_KEY && export CC_NODE_API_KEY   # bash; typed, not echoed
# or from a mode-0600 file; read -r drops the final newline:
read -r CC_NODE_API_KEY < write.token && export CC_NODE_API_KEY
cc-publisher v1 submit --node https://node.example --dir entry/
unset CC_NODE_API_KEY
```

## Commands

### keygen

```sh
cc-publisher v1 keygen --out FILE
```

Writes a new seed from the operating-system RNG to `FILE` as described in
[Key files](#key-files), then prints its public key as 64 hex characters.
Exit 1 if `FILE` exists or cannot be created, linked or read back.

### pubkey

```sh
cc-publisher v1 pubkey --key FILE
```

Prints the Ed25519 public key of a key file: the `author` of its events and
the value a node lists in `curators`. The file must pass the loading checks.

### node-info

```sh
cc-publisher v1 node-info --node URL
```

Sends `GET /health` without a token and prints JSON:

| Field | Meaning |
|---|---|
| `node` | Base URL as used, with a trailing `/` |
| `health` | `ledger`, `build`, `posture`, `semantic`, `instance`, `fold_version` (`version`, `manifest`), `filter_version`, `curators`, `max_hops` |
| `build_fold_version` | This build's `fold_v1()`: version 1 and the SHA-256 of `crates/cc-core/src/v1/fold-manifest-v1.txt` |
| `fold_matches_build` | `health.fold_version` equals `build_fold_version` |
| `filter_version_consistent` | `filter_version` equals the governed filter identity this build computes from `curators` and `max_hops`; false if the curators are empty, unsorted or invalid keys, or `max_hops` is 0 |

It prints, then exits 1, when `fold_matches_build` is false. It exits 1
without output when `/health` is not HTTP 200 or lacks a field above (`build`
is optional). Nothing else is enforced; read the other fields yourself.

### genesis

```sh
cc-publisher v1 genesis --key FILE --instance HEX --kind TT_NODE_ID \
  --namespace NS --value V --body FILE --asserted-time T \
  [--evidence SHA256 ...] [--nonce HEX] --out DIR
```

Offline. Every argument is checked before the key is loaded. Nothing is
written until the envelope is signed and has passed the self-check.

| Flag | Rule |
|---|---|
| `--key` | Key file; see [Key files](#key-files). |
| `--instance` | 64 hex. `submit` requires it to equal the node's instance. |
| `--kind` | A current node id of the pinned TT taxonomy `vendor/tt/taxonomy-v2.1.json`: `tt-ontology/1.0 v2.1.0`, SHA-256 `31ed385e26522a5b548f7404f7757ee370ed9783dbd550b05cd69e89e9462113`. An unknown id is refused. A retired id is refused with its successor named. |
| `--namespace`, `--value` | Nonempty UTF-8, at most 1024 bytes, no control characters, no leading or trailing whitespace. A value that begins with `-` must be attached with `=`, as in `--value=-x`. |
| `--body` | A file of nonempty UTF-8, at most 1 MiB (1,048,576 bytes). |
| `--asserted-time` | See [Asserted time](#asserted-time). A leading `-` needs no `=`. |
| `--evidence` | Optional and repeatable; one flag may also take several values. Each is a SHA-256 hash in 64 hex; the tool does not read the evidence itself. Sorted into ascending order. Duplicates are refused. At most 1024. |
| `--nonce` | Optional, 64 hex. Default: 32 bytes from the operating-system RNG. |
| `--out` | Absent, or an empty directory. |

The body must be UTF-8 because the node serves prose as a JSON string and
`submit` compares the served bytes with `body.bin`. 1 MiB is the largest body
`PUT /v1/bodies/{sha256}` accepts. The bytes are signed as they are: line
endings, a byte-order mark and a final newline are not normalized.

The namespace and value rules keep the signed key equal to what a reviewer
sees. "Control characters" means Unicode category Cc and "whitespace" means
Unicode White_Space. Invisible format characters (category Cf, such as
zero-width and bidirectional marks) are not refused, so keep these fields to
visible text.

With the same key, inputs and `--nonce`, `genesis` writes identical bytes;
Ed25519 signing is deterministic. Without `--nonce`, each run is a new event
and a new subject. Submit only the directory that was reviewed.

#### Asserted time

Proleptic Gregorian with astronomical year numbering (year `0000` is 1 BCE,
`-0043` is 44 BCE):

| Input        | `precision` | Instant encoded in `coordinate`     |
| ------------ | ----------- | ----------------------------------- |
| `YYYY`       | `year`      | 00:00:00 UTC on 1 January of `YYYY` |
| `YYYY-MM`    | `month`     | 00:00:00 UTC on day 1 of that month |
| `YYYY-MM-DD` | `day`       | 00:00:00 UTC on that day            |

Exactly four year digits with an optional leading `-`, two month digits and
two day digits; nothing else (no time of day, zone or whitespace). `-0000` is
refused because `0000` names the same year. The month and day must exist.

The coordinate is the `cc_core::Tick` of that instant: whole seconds since
J2000.0 (2000-01-01T12:00:00 UTC), counting every day as 86,400 seconds,
shifted left by the governed 64 fractional bits, and serialized by
`Tick::to_canon_bytes`: 32 bytes, big-endian, offset-binary (two's complement
with the top bit flipped). It is the mapping `cc_authoring::year_tick` and the
v0 publisher's day precision use.

Worked example, `--asserted-time 1901-02-03`:

| Step | Value |
|---|---|
| Days since 1970-01-01 | -25,169 |
| Seconds since J2000.0 | -25,169 x 86,400 - 946,728,000 = -3,121,329,600 |
| Seconds as 64-bit two's complement | `ffffffff45f44a40` |
| `precision` | `day` |
| `coordinate` | `7fffffffffffffffffffffffffffffffffffffff45f44a400000000000000000` |

Bytes 16 to 23 of the coordinate hold the seconds. Bytes 24 to 31, the
fraction, are zero.

#### Output

When `DIR` is absent it is created, with its parents, mode 0700. An existing
empty directory keeps its mode. `body.bin`, `envelope.bin` and `preview.json`
are each created as new files with mode 0600 and synced; an existing file is
never replaced. The umask can only narrow these modes.

Before anything is written, the signed envelope is decoded again (canonical
form and signature) and classified with `cc_ledger::v1::classify`, the node's
own branch-local admission rule. Anything but `valid` is refused.

Stdout carries a review summary: instance, author, subject key, asserted time
(calendar form, precision, coordinate), body size and SHA-256, the body's
first line (at most 100 characters, quoted), evidence, nonce, event, subject,
revision, and envelope size and SHA-256. Nothing is sent to a node.

### submit

```sh
cc-publisher v1 submit --node URL --dir DIR [--allow-untrusted]
```

Needs `CC_NODE_API_KEY`. The token and URL are checked first. Steps 1 to 5
only read; the first write is step 6.

1. Reload `DIR` and rerun every `genesis` check. `envelope.bin` (at most
   1 MiB) must decode as canonical `cc.event.v1` with a valid signature and be
   a Genesis. Kind, namespace, value and body must pass the `genesis` rules.
   `body.bin` must hash to the body the envelope signs. The envelope must
   classify `valid`. `preview.json` must equal the preview recomputed from the
   two files, compared as JSON values. No key is needed.
2. `GET /health`: HTTP 200 and a v1 health document.
3. Refuse, whatever the flags, unless `ledger` is `v1`, `posture` is not
   `frozen` and `semantic` is `ready`.
4. Trust checks: `instance` equals the envelope's; `fold_version` equals this
   build's `fold_v1()`; the author is in `curators`; `filter_version` is
   consistent, as in `node-info`. Any failure refuses with
   `refusing to submit; nothing was written` and one line per failed check.
   With `--allow-untrusted` the submit continues. The messages are printed to
   stderr as `warning (--allow-untrusted): ...` after a successful run. The
   receipt's `trust` block records each check and `allow_untrusted`, not the
   messages.
5. `GET /v1/subjects/{subject}`. HTTP 404, or 200 with visibility
   `subject_unknown`, means not yet known. If the node already knows the
   subject, this Genesis was admitted before: it is reported as
   `already_admitted` and never posted again.
6. `PUT /v1/bodies/{sha256}` with `body.bin`. HTTP 201 is `stored` and 200 is
   `already_present`; anything else is an error. This runs on every submit.
7. Unless already admitted, `POST /v1/candidates` with `envelope.bin`. It
   requires HTTP 201 and state `valid`, an outcome `event` equal to the event
   id, and an `input_digest` equal to the SHA-256 of `envelope.bin`. 202
   (pending) and 422 (invalid) fail with the node's state and reason.
8. Read back `GET /v1/subjects/{subject}`. The node must answer for this
   subject with state `resolved` and visibility `visible`. Its current
   revision must be this Genesis's revision and bind this subject, this event
   as `creating_event`, the body hash and the envelope's asserted time.
9. `GET /v1/revisions/{revision}/prose`. It must answer for this revision with
   availability `available`, and the prose string's UTF-8 bytes must equal
   `body.bin` exactly.
10. Write `DIR/receipt.json` (new file, mode 0600) only if it does not exist.
    The receipt is printed to stdout either way. Stderr says
    `receipt written to ...` or `... already exists; left unchanged`.

Exit 0 when step 9 passed. A rerun is safe: an admitted Genesis is not posted
again, the body `PUT` returns 200, and the read-back runs again. If a step
after the `POST` fails, the envelope may be admitted with no receipt written;
fix the cause and rerun to complete the receipt. `receipt.json` keeps the first
successful result; redirect stdout to keep a later one. The read-back requires
this Genesis's revision to be current, so once a later event replaces it, use
`verify` instead.

### verify

```sh
cc-publisher v1 verify --node URL --subject HEX [--dir DIR]
```

Read-only: it sends only `GET` requests. It needs `CC_NODE_READ_KEY`, or
`CC_NODE_API_KEY` when that is unset. `--subject` is the subject id, which for
a Genesis is its event id. With `--dir`, the directory is first reloaded with
the checks of `submit` step 1. Each failed check adds an entry to `failures`:

| Check | Failure entry |
|---|---|
| `/health` `ledger` is `v1` | `node ledger is "...", not "v1"` |
| `fold_version` equals `fold_v1()` | `node fold_version differs from this build` |
| The node knows the subject | `node does not know the subject` |
| It answers for that subject | `node answered for another subject` |
| State `resolved`, visibility `visible` | `subject is not resolved and visible` |
| A current revision with an id and body hash | `subject has no current revision`, `current revision lacks an id or body hash` |
| That revision's prose is available | `prose availability is ...` |
| The served prose hashes to the revision's body hash | `served prose does not hash to the revision body` |
| With `--dir`: the same subject | `--dir holds a different subject` |
| With `--dir`: the node's instance | `node instance differs from the --dir envelope` |
| With `--dir`: the author is a curator | `--dir author is not in the node's curator set` |
| With `--dir`: exactly this revision and `body.bin` | `node does not serve the --dir Genesis revision with body.bin's exact bytes` |

Posture, semantic readiness and filter consistency are not checked, and
without `--dir` neither are instance and curators.

Stdout is a JSON report: `node`, `node_health`, `subject`; `state`,
`visibility` and `frontier` when the node knows the subject; `revision`
(`id`, `creating_event`, `body`, `asserted_time` as `calendar`, `precision`,
`coordinate`) when there is a current revision; `prose` (`bytes`, `sha256`,
`matches_revision_body`) when prose is available; `local` (`event`,
`revision`, `body_sha256`) with `--dir`; then `ok` and `failures`.

Exit 0 when `ok` is true. Otherwise the report is printed and the command
exits 1 with `verification failed`. Errors before a report exists exit 1
without one: a bad URL, token, `--subject` or `--dir`, an unreachable node, a
malformed `/health`, or an unexpected HTTP status, including from the prose
route.

## Output files

### envelope.bin

The canonical `cc.event.v1` preimage followed by a 64-byte Ed25519 signature
over it by the author's key; at most 1 MiB. In the preimage, integers are
big-endian, a string is a u32 byte length and UTF-8, an optional field is one
byte 0 or 1 and then the value, and a set is a u32 count and strictly
ascending items. A Genesis preimage holds, in order:

| Field | Genesis value |
|---|---|
| encoding | string `cc.event.v1` |
| canon and constants versions | u16 `1`, u16 `0` |
| instance | 32 bytes |
| kind | u16 `1` (Genesis) |
| author | 32-byte Ed25519 public key |
| subject, then subject key | absent; present: kind, namespace, value strings |
| grant, then parents | absent; empty set |
| asserted time | present: 32-byte coordinate, precision string |
| payload | nonce (32 bytes), body SHA-256 (32 bytes), evidence set |

### body.bin

The exact `--body` bytes. Its SHA-256 is the body hash the envelope signs and
the `{sha256}` of `PUT /v1/bodies/{sha256}`.

### preview.json

A pure function of `envelope.bin` and `body.bin`. `submit` and `verify --dir`
recompute it and refuse a mismatch.

| Field | Meaning |
|---|---|
| `schema` | `cc.publisher.v1.preview` |
| `event_kind`, `encoding` | `genesis`, `cc.event.v1` |
| `canon_version`, `constants_version` | `1`, `0` |
| `instance` | Instance id |
| `event` | Event id |
| `subject` | Subject id; equal to `event` |
| `revision` | Revision id this Genesis creates |
| `root_grant` | Id of the grant this Genesis issues to its author for the subject |
| `author` | Signer's Ed25519 public key |
| `nonce` | Genesis nonce |
| `subject_key` | `kind`, `namespace`, `value` as signed |
| `asserted_time` | `calendar` (the canonical input form, or null if the coordinate is not exactly the start of a period of that precision), `precision`, `coordinate` |
| `body_sha256`, `body_bytes` | SHA-256 and length of `body.bin` |
| `evidence` | Evidence hashes in ascending order |
| `envelope_sha256`, `envelope_bytes` | SHA-256 and length of `envelope.bin`; the node calls the SHA-256 `input_digest` |
| `taxonomy` | `version` and `sha256` of the pinned TT taxonomy |

### receipt.json

Written by `submit` (step 10).

| Field | Meaning |
|---|---|
| `schema` | `cc.publisher.v1.receipt` |
| `node` | Base URL as used |
| `node_health` | `/health` as read: `ledger`, `build`, `posture`, `semantic`, `instance`, `fold_version`, `filter_version`, `curators`, `max_hops` |
| `trust` | `instance_matches`, `fold_matches`, `author_is_curator`, `filter_version_consistent`, `allow_untrusted` |
| `event`, `subject`, `revision`, `author`, `instance` | As in `preview.json` |
| `body_sha256`, `envelope_sha256` | As in `preview.json` |
| `body` | `http_status` and `result`: 201 `stored` or 200 `already_present` |
| `admission` | `result` `admitted`, `http_status` 201 and the node's `outcome` (`event`, `input_digest`, `state`, `reason`); or `result` `already_admitted` with `http_status` and `outcome` null |
| `readback` | `subject_state` `resolved`, `visibility` `visible`, `frontier`, `revision`, `asserted_time` (calendar form), `prose_bytes`, `prose_sha256`, `prose_equals_body_bin` `true`, and the node's `rule`, `corpus_digest` and `commitment` (null if absent) |

### Identifiers

`frame(d)` is the byte length of the ASCII string `d` as a 4-byte big-endian
integer, followed by `d`.

- Event id: SHA-256 of the preimage. The signature is not part of it.
- Subject id: the event id, for a Genesis.
- Revision id: SHA-256(frame("cc.revision.v1") || subject || event).
- Root grant: SHA-256(frame("cc.root-grant.v1") || event).
- Input digest: SHA-256 of `envelope.bin`, signature included.
- Body hash: SHA-256 of `body.bin`.

## Refusals and errors

| Message contains | Cause | Fix |
|---|---|---|
| `must be set in the environment` | Token variable unset | Export it; see [Typical sequence](#typical-sequence) |
| `is set but empty`, `node token is empty` | Blank token variable | Set the token, or unset a blank `CC_NODE_READ_KEY` |
| `characters not allowed in a header` | Newline or control character in the token | Read it with `read -r` |
| `refusing plain http to` | `http://` to a dotted name or non-loopback IP | Use `https://` |
| `unsupported node URL scheme`, `invalid node URL` | Not an absolute http(s) URL | Pass the base URL with its scheme |
| `must not carry credentials`, `query or fragment` | User info, `?` or `#` in `--node` | Pass the bare base URL |
| `HTTP 301`, `HTTP 308` and other 3xx | Redirect | Use the final URL |
| `HTTP 401`, `HTTP 403` | Missing, wrong or too narrow token | Use the write key for `submit` |
| `GET /health:` and a connection or timeout error | Node unreachable, TLS failure or proxy | Check URL, network, certificate and proxy variables |
| `/health lacks` | Not a v1 node | Check the URL and the node's mode |
| `refusing to overwrite existing` | `keygen` target exists | Choose a new path |
| `open key file` | Key file missing | Check the path |
| `is wider than 0600` | Key file mode | `chmod 600 FILE` |
| `must hold exactly 64 hex characters and an optional newline` | Key file content | Restore the seed file unchanged |
| `is not a node id in the pinned TT taxonomy` | Unknown kind | Use a node id from `vendor/tt/taxonomy-v2.1.json` |
| `is retired in the pinned TT taxonomy; its successor is` | Retired kind, for example `everyday-movement-and-commute` | Use the named successor, here `journey-and-travel` |
| `must not be empty`, `exceeds 1024 bytes`, `control characters`, `start or end with whitespace` | Namespace or value | Correct the field |
| `must be YYYY, YYYY-MM or YYYY-MM-DD`, `month must be 01-12`, `no such day` | Asserted time | See [Asserted time](#asserted-time) |
| `write year 0000 without a sign` | `-0000` | Use `0000` |
| `body must not be empty`, `body must be UTF-8 text`, `exceeds 1048576 bytes` | Body | Supply nonempty UTF-8 of at most 1 MiB |
| `duplicate evidence hash`, `at most 1024 evidence hashes` | Evidence | Pass each hash once |
| `refusing to write into non-empty`, `exists and is not a directory` | `--out` | Use a new directory |
| `does not hash to the body the envelope signs`, `does not match envelope.bin and body.bin`, `envelope.bin:` | `DIR` changed after `genesis`, or a build with another pinned taxonomy | Run `genesis` again into a new directory and review it |
| `cc_ledger::v1 classifies this Genesis as` | Self-check failed | Report it; inputs checked by the CLI should not reach this |
| `node reports ledger`, `posture is frozen`, `semantic readiness is` | Node not writable in v1 mode | Wait for the node operator; no flag overrides this |
| `refusing to submit; nothing was written` | A trust check failed; the lines name which | Use the right node, instance, key or build |
| `node did not admit the envelope as valid` | HTTP 202 pending or 422 invalid | Read the state and reason |
| `node acknowledged a different envelope` | Outcome names another event or digest | Stop and investigate the node |
| `readback:` | The node does not serve what was signed | Investigate; rerun `submit` once fixed |
| `verification failed` | `verify` found failures | Read `failures` in the report |
