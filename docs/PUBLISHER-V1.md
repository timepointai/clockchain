# Publisher v1

`cc-publisher v1` signs a v1 Genesis offline, submits it to a node running in
v1 mode, and reads it back. The contract is in the "Publisher CLI" and "HTTP in
v1 mode" sections of [STAGE-F.md](design/STAGE-F.md). This page describes what
the code does.

## Scope

- `keygen`, `pubkey` and `genesis` work offline; `node-info`, `submit` and
  `verify` use only the node's HTTP API. No `v1` command opens a database or
  reads `DATABASE_URL`. The envelope is built with the `cc_core::v1` types the
  node decodes. Only Genesis events are built. The v0 commands are unchanged.
- Hex arguments (`--instance`, `--evidence`, `--nonce`, `--subject`) are
  exactly 64 hex characters, either case. Printed hex is lowercase.
- Exit status is 0 on success and 1 on any refusal or failure, with
  `cc-publisher v1: ` and the error's causes, joined by `: `, on stderr.
  Parser errors, such as a missing flag, exit 2. `--help` lists the flags.

## Security model

### Secrets

The signing seed is read only from the `--key` file. Node tokens are read only
from the environment. No flag takes a secret.

| Command | Token |
|---|---|
| `submit` | `CC_NODE_API_KEY` (write) |
| `verify` | `CC_NODE_READ_KEY`; `CC_NODE_API_KEY` only when `CC_NODE_READ_KEY` is unset |
| `node-info` | None; `/health` is public |

A variable that is set but blank is refused; it does not fall back. A token
with leading or trailing whitespace is refused. The token is sent as
`Authorization: Bearer <token>` exactly as set, so it must not contain a
newline or other control character. It goes only to the authenticated routes:
never to `/health`, which is public. Tokens and seeds are never printed. An
error that quotes a response body (at most 300 characters) replaces the token
with `<redacted>` in case the node echoes it, and a key-file error does not
quote the file.

### Key files

A key file holds a 32-byte Ed25519 seed (RFC 8032) as exactly 64 hex
characters, either case, and an optional final newline; nothing else, not even
a carriage return. `keygen` writes 64 lowercase hex characters and a newline.
The seed is not encrypted; protect the file and any copy.
`keygen` refuses a target that exists, a dangling symlink included. It writes
the seed to a new file `.<name>.<16 hex>.tmp` beside the target, created
exclusively with mode exactly 0600 whatever the umask, syncs it and hard-links
it to the target. The link fails if the target has appeared meanwhile, so no
file is ever replaced and the target never appears partially written. It then
removes the temporary file, syncs the directory and reads the key back. The
directory must exist and support hard links. An interrupted `keygen` may leave
the temporary file, which holds a seed; delete it.

Loading (`pubkey`, `genesis`) refuses anything but a regular file (a symlink
is followed) and opens it non-blocking, so a FIFO or device cannot block the
command. It then checks the opened file before reading it: its mode must have
none of setuid, setgid, sticky, owner execute, or any group or other bit
(mask `07177`). Modes 0600 and 0400 pass; 0640, 0644 and 0700 are refused.
The body file and the files `submit` reloads get the same regular-file check.

### Node URL and transport

- `--node` takes an absolute base URL. `https://` is accepted for any host.
  `http://` is accepted only for loopback IP literals (`127.0.0.0/8`,
  `[::1]`), `localhost` and single-label host names without a dot, such as a
  container name on a private Docker network. Any dotted name and any other IP
  literal needs `https://`. The rule exists so a bearer token never crosses
  the public internet in clear text.
- Other schemes, user info, a query and a fragment are refused. A path is a
  prefix: `https://node.example/cc` sends `https://node.example/cc/health`.
- Redirects are never followed; a 3xx is an error, so a token is never
  replayed to another URL. Connecting times out after 15 s and each request
  after 120 s. A response over 16 MiB is refused. TLS uses rustls with the
  bundled Mozilla roots (webpki-roots), not the operating-system trust store,
  so a private-CA certificate fails.
- For `https://`, `HTTPS_PROXY`, `ALL_PROXY` and `NO_PROXY` are honored; a
  proxy sees only the TLS tunnel. For plain `http://`, every proxy variable is
  ignored and the request goes direct, so the token is never handed to a
  proxy in clear text. A DNS search domain can turn a single-label name into
  a remote one, so use plain http only on a private network.

## Typical sequence

Words in capitals are placeholders. `entry/` must be absent or empty.

```sh
cc-publisher v1 keygen --out curator.seed   # offline; prints the public key
cc-publisher v1 pubkey --key curator.seed   # offline; prints it again
cc-publisher v1 node-info --node https://node.example   # check its identity
cc-publisher v1 genesis --key curator.seed --instance INSTANCE_HEX \
  --kind TT_NODE_ID --namespace NAMESPACE --value VALUE \
  --body body.txt --asserted-time YYYY-MM-DD \
  --evidence EVIDENCE_SHA256 --out entry/     # offline
# Review entry/body.bin and entry/preview.json. SUBJECT_HEX is its "subject".
CC_NODE_API_KEY=... cc-publisher v1 submit --node https://node.example --dir entry/
CC_NODE_READ_KEY=... cc-publisher v1 verify --node https://node.example \
  --subject SUBJECT_HEX --dir entry/
```

A real token typed into a command line is saved in shell history. Read it into
the environment instead, drop the `VAR=...` prefix, and unset it when done.
`read` also drops the final newline, which a token must not contain.

```sh
read -rs CC_NODE_API_KEY && export CC_NODE_API_KEY   # bash; typed, not echoed
read -r CC_NODE_API_KEY < write.token; export CC_NODE_API_KEY   # or a 0600 file
unset CC_NODE_API_KEY CC_NODE_READ_KEY
```

## Commands

### keygen

```sh
cc-publisher v1 keygen --out FILE
```

Writes a new seed from the operating-system RNG to `FILE` (see
[Key files](#key-files)) and prints its public key as 64 hex characters.
Exit 1 if `FILE` exists or cannot be written, linked or read back.

### pubkey

```sh
cc-publisher v1 pubkey --key FILE
```

Prints a key file's Ed25519 public key: the `author` of its events, as a
node lists it in `curators`. Exit 1 if the file fails the loading checks.

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
is optional). Nothing else is enforced; check the other fields yourself.

### genesis

```sh
cc-publisher v1 genesis --key FILE --instance HEX --kind TT_NODE_ID \
  --namespace NS --value V --body FILE --asserted-time T \
  [--evidence SHA256 ...] [--nonce HEX] --out DIR
```

Offline. Every argument, `--out` included, is checked before the key is
loaded; `--out` is checked again when the files are written.

| Flag | Rule |
|---|---|
| `--key` | Key file; see [Key files](#key-files). |
| `--instance` | 64 hex. `submit` requires it to equal the node's instance. |
| `--kind` | A current node id of the pinned TT taxonomy `vendor/tt/taxonomy-v2.1.json`: `tt-ontology/1.0 v2.1.0`, SHA-256 `31ed385e26522a5b548f7404f7757ee370ed9783dbd550b05cd69e89e9462113`. An unknown id is refused. A retired id is refused with its successor named. |
| `--namespace`, `--value` | Nonempty UTF-8, at most 1024 bytes, no control characters, no invisible or bidirectional characters, no leading or trailing whitespace. A value that begins with `-` must be attached with `=`, as in `--value=-x`. |
| `--body` | A regular file of nonempty UTF-8, at most 1 MiB (1,048,576 bytes). |
| `--asserted-time` | See [Asserted time](#asserted-time). A leading `-` needs no `=`. |
| `--evidence` | Optional and repeatable; one flag may also take several values. Each is a SHA-256 hash in 64 hex; the tool does not read the evidence itself. Sorted into ascending order. Duplicates are refused. At most 1024. |
| `--nonce` | Optional, 64 hex. Default: 32 bytes from the operating-system RNG. |
| `--out` | Absent, or an empty directory. |

The body must be UTF-8 because the node serves prose as a JSON string and
`submit` compares the served bytes with `body.bin`; 1 MiB is the largest body
`PUT /v1/bodies/{sha256}` accepts. The bytes are signed as they are; line
endings, a byte-order mark and a final newline are not normalized.

The namespace and value rules keep the signed key equal to what a reviewer
sees. Control characters are Unicode category Cc and whitespace is Unicode
White_Space. Also refused, wherever they appear: the soft hyphen, zero-width
spaces and joiners, bidirectional marks, embeddings, overrides and isolates,
invisible operators, Hangul and Mongolian fillers and selectors, variation
selectors, the byte-order mark, interlinear annotation characters and tag
characters (`genesis::is_invisible`). The error names the code point.

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
`Tick::to_canon_bytes` as 32 bytes, big-endian, offset-binary (two's
complement with the top bit flipped). It is the mapping
`cc_authoring::year_tick` and the v0 publisher's day precision use.

Worked example, `--asserted-time 1901-02-03` (precision `day`):

| Step | Value |
|---|---|
| Days since 1970-01-01 | -25,169 |
| Seconds since J2000.0 | -25,169 x 86,400 - 946,728,000 = -3,121,329,600 |
| Seconds as 64-bit two's complement | `ffffffff45f44a40`, in bytes 16 to 23; bytes 24 to 31 are zero |
| `coordinate` | `7fffffffffffffffffffffffffffffffffffffff45f44a400000000000000000` |

#### Output

When `DIR` is absent it is created, with its parents, mode 0700. An existing
empty directory keeps its mode. `body.bin`, `envelope.bin` and `preview.json`
are each created as new files with mode 0600 and synced; an existing file is
never replaced. The umask can only narrow these modes.
Before anything is written, the signed envelope is decoded again (canonical
form and signature) and classified with `cc_ledger::v1::classify`, the node's
own branch-local admission rule. Anything but `valid` is refused. Stdout then
carries a review summary of the signed fields and identifiers, with the body's
first line (at most 100 characters, quoted). Exit 0 once the three files are
written. A refusal exits 1 with nothing written; if writing itself fails,
remove `DIR` and run again.

### submit

```sh
cc-publisher v1 submit --node URL --dir DIR [--allow-untrusted]
```

Needs `CC_NODE_API_KEY`; the token and URL are checked first. Steps 1 to 5
only read.

1. Reload `DIR` with the signing checks: `envelope.bin` (at most 1 MiB) is a
   canonical, correctly signed `cc.event.v1` Genesis; kind, namespace, value
   and body pass the `genesis` rules; `body.bin` hashes to the signed body
   hash; the envelope classifies `valid`; and `preview.json` equals the
   preview recomputed from the two files, compared as JSON. No key is needed.
2. `GET /health`: HTTP 200 and a v1 health document.
3. Refuse, whatever the flags, unless `ledger` is `v1`, `posture` is not
   `frozen` and `semantic` is `ready`.
4. Trust checks: `instance` equals the envelope's, `fold_version` equals this
   build's `fold_v1()`, the author is in `curators`, and `filter_version` is
   consistent (see `node-info`). Failures are refused, one line each, under
   `refusing to submit; nothing was written`. `--allow-untrusted` continues:
   each overridden check is printed to stderr as
   `warning: --allow-untrusted overrides: ...` before anything is written, and
   recorded in the receipt's `trust.overridden`.
5. `GET /v1/subjects/{subject}`. HTTP 404, or 200 with visibility
   `subject_unknown`, means not yet known. Otherwise this Genesis was admitted
   before; it is reported as `already_admitted` and never posted again.
6. `PUT /v1/bodies/{sha256}` with `body.bin`, on every run: 201 is `stored`,
   200 is `already_present`, anything else an error.
7. Unless already admitted, `POST /v1/candidates` with `envelope.bin`. It
   requires HTTP 201, state `valid`, the event id as `event`, and the SHA-256
   of `envelope.bin` as `input_digest`. 202 (pending) and 422 (invalid) fail
   with the node's state and reason.
8. Read back `GET /v1/subjects/{subject}`: this subject, `resolved` and
   `visible`, its current revision this Genesis's revision, binding the
   subject, this event as `creating_event`, the body hash and asserted time.
9. `GET /v1/revisions/{revision}/prose`: this revision, availability
   `available`, and prose whose UTF-8 bytes equal `body.bin` exactly.
10. Write `DIR/receipt.json` (new file, mode 0600) only if it does not exist.

Stdout is the receipt JSON either way. Stderr then has one line each for
`body`, `envelope`, `readback` and `receipt`; the last reads
`receipt   written to DIR/receipt.json` or
`receipt   DIR/receipt.json already exists; left unchanged`. Exit 0.

A rerun is safe: an admitted Genesis is not posted again, the body `PUT`
returns 200 and the read-back runs again. If a step after the `POST` fails,
the envelope may be admitted with no receipt; fix the cause and rerun. The
file keeps the first successful result, even when a later run uses another
node or no overrides; redirect stdout to keep a later one. The read-back
needs this Genesis's revision to be current; once a later event replaces it,
use `verify`.

### verify

```sh
cc-publisher v1 verify --node URL --subject HEX [--dir DIR]
```

Read-only: it sends only `GET` requests. It needs `CC_NODE_READ_KEY`, or
`CC_NODE_API_KEY` when that is unset; with neither set, the error names both.
`--subject` is the subject id, which for a Genesis is its event id. With
`--dir`, the directory is first reloaded with the checks of `submit` step 1.
Each failed check adds an entry to `failures`:

| Check | Failure entries |
|---|---|
| `/health` reports `ledger` `v1` and this build's `fold_v1()` | `node ledger is "...", not "v1"`; `node fold_version differs from this build` |
| The node knows the subject and answers for it | `node does not know the subject`; `node answered for another subject` |
| `resolved` and `visible`, with a current revision that has an id and body hash | `subject is not resolved and visible`; `subject has no current revision`; `current revision lacks an id or body hash` |
| That revision's prose answers for it, is available and hashes to its body hash | `prose answered for another revision`; `prose availability is ...` (a failed read gives `"read failed: ..."`); `served prose does not hash to the revision body` |
| With `--dir`: same subject, the node's instance, author in `curators` | `--dir holds a different subject`; `node instance differs from the --dir envelope`; `--dir author is not in the node's curator set` |
| With `--dir`: exactly this revision and `body.bin` | `node does not serve the --dir Genesis revision with body.bin's exact bytes` |

Posture, semantic readiness and filter consistency are not checked, and
without `--dir` neither are instance and curators. Stdout is a JSON report:
`node`, `node_health`, `subject`; what was served (`state`, `visibility`,
`frontier`, `revision`, `prose`) as far as it got; `local` (`event`,
`revision`, `body_sha256`) with `--dir`; then `ok` and `failures`.

Exit 0 when `ok` is true. Otherwise the report is printed and the command
exits 1 with `verification failed`. Some errors stop it earlier and exit 1
with no report: a bad URL, token, `--subject` or `--dir`, or a failed
`/health` or subject read.

## Output files

### envelope.bin and body.bin

`envelope.bin` is the canonical `cc.event.v1` preimage followed by a 64-byte
Ed25519 signature over it by the author's key; at most 1 MiB. In the preimage,
integers are big-endian, a string is a u32 byte length and UTF-8, an optional
field is one byte 0 or 1 and then the value, and a set is a u32 count and
strictly ascending items. A Genesis preimage holds, in order: the string
`cc.event.v1`; u16 canon version `1` and u16 constants version `0`; the
32-byte instance; u16 kind `1`; the 32-byte author key; no subject; the
subject key (kind, namespace and value strings); no grant; an empty parents
set; the asserted time (32-byte coordinate, precision string); then the
nonce, the body SHA-256 and the evidence set.

`body.bin` is the exact `--body` bytes. Its SHA-256 is the body hash the
envelope signs and the `{sha256}` of `PUT /v1/bodies/{sha256}`.

### preview.json

A pure function of `envelope.bin` and `body.bin`. `submit` and `verify --dir`
recompute it and refuse a mismatch.

| Field | Meaning |
|---|---|
| `schema` | `cc.publisher.v1.preview` |
| `event_kind`, `encoding`, `canon_version`, `constants_version` | `genesis`, `cc.event.v1`, `1`, `0` |
| `instance`, `event`, `subject` | Instance id; event id; subject id, equal to the event id |
| `revision`, `root_grant` | Revision id this Genesis creates; id of the grant it issues to its author for the subject |
| `author`, `nonce` | Signer's Ed25519 public key; Genesis nonce |
| `subject_key` | `kind`, `namespace`, `value` as signed |
| `asserted_time` | `calendar` (the canonical input form, or null if the coordinate is not exactly the start of a period of that precision), `precision`, `coordinate` |
| `body_sha256`, `body_bytes` | SHA-256 and length of `body.bin` |
| `evidence` | Evidence hashes in ascending order |
| `envelope_sha256`, `envelope_bytes` | SHA-256 and length of `envelope.bin`; the node calls the SHA-256 `input_digest` |
| `taxonomy` | `version` and `sha256` of the pinned TT taxonomy |

### receipt.json

Written by `submit` (step 10). It records what the node answered, checked
against what was signed. Every value it checks can be derived from the bytes
the publisher sent, so a node that answers dishonestly could pass; the receipt
is the node's claim of retention, not a proof of it.

| Field | Meaning |
|---|---|
| `schema` | `cc.publisher.v1.receipt` |
| `node` | Base URL as used |
| `node_health` | `/health` as read: `ledger`, `build`, `posture`, `semantic`, `instance`, `fold_version`, `filter_version`, `curators`, `max_hops` |
| `trust` | `instance_matches`, `fold_matches`, `author_is_curator`, `filter_version_consistent`, `allow_untrusted`, and `overridden`: the message of each failed check that `--allow-untrusted` overrode (empty otherwise) |
| `event`, `subject`, `revision`, `author`, `instance`, `body_sha256`, `envelope_sha256` | As in `preview.json` |
| `body` | `http_status` and `result`: 201 `stored` or 200 `already_present` |
| `admission` | `result` `admitted`, `http_status` 201 and the node's `outcome` (`event`, `input_digest`, `state`, `reason`); or `result` `already_admitted` with `http_status` and `outcome` null |
| `readback` | `subject_state` `resolved`, `visibility` `visible`, `frontier`, `revision`, `asserted_time` (calendar form), `prose_bytes`, `prose_sha256`, `prose_equals_body_bin` `true`, and the node's `rule`, `corpus_digest` and `commitment` (null if absent) |

### Identifiers

With `frame(d)` the byte length of the ASCII string `d` as a 4-byte
big-endian integer, followed by `d`:

- Event id: SHA-256 of the preimage. The signature is not part of it.
- Subject id: the event id, for a Genesis.
- Revision id: SHA-256(frame("cc.revision.v1") || subject || event).
- Root grant: SHA-256(frame("cc.root-grant.v1") || event).
- Input digest: SHA-256 of `envelope.bin`; body hash: SHA-256 of `body.bin`.

## Refusals and errors

| Message contains | Cause | Fix |
|---|---|---|
| `must be set in the environment`, `is set but empty`, `node token is empty` | Token variable unset or blank | Set it; unset a blank `CC_NODE_READ_KEY` to fall back |
| `node token must not start or end with whitespace` | Padded token | Read it with `read -r`; tokens are never trimmed |
| `characters not allowed in a header` | Newline or control character in the token | Read it with `read -r` |
| `refusing plain http to` | `http://` to a dotted name or non-loopback IP | Use `https://` |
| `unsupported node URL scheme`, `invalid node URL`, `must not carry` | Not a bare absolute http(s) base URL | Pass scheme, host, optional port and path only |
| `HTTP 301`, `HTTP 308` and other 3xx | Redirect | Use the final URL |
| `HTTP 401`, `HTTP 403` | Missing, wrong or too narrow token | Check the token; `submit` needs the write key |
| `GET /health:` and a connection or timeout error | Node unreachable, TLS failure or proxy | Check URL, network, certificate and proxy variables |
| `/health lacks` or another `/health` field error | Not a v1 node | Check the URL and the node's mode |
| `must be 64 hex characters` | A hex argument | Pass exactly 64 hex characters |
| `refusing to overwrite existing` | `keygen` target exists | Choose a new path |
| `open key file`, `is not a regular file`, `must hold exactly 64 hex characters`, `is wider than 0600` | Wrong key path, content or mode | Point `--key` at the unchanged seed file; `chmod 600` it |
| `is not a node id in the pinned TT taxonomy` | Unknown kind | Use a node id from `vendor/tt/taxonomy-v2.1.json` |
| `is retired in the pinned TT taxonomy; its successor is` | Retired kind, for example `everyday-movement-and-commute` | Use the named successor, here `journey-and-travel` |
| `must not be empty`, `exceeds 1024 bytes`, `control characters`, `invisible or bidirectional characters (found U+...)`, `start or end with whitespace` | Namespace or value | Correct the field; retype it if the character is not visible |
| `must be YYYY, YYYY-MM or YYYY-MM-DD`, `month must be 01-12`, `no such day`, `without a sign` | Asserted time | See [Asserted time](#asserted-time) |
| `body must not be empty`, `body must be UTF-8 text`, `exceeds 1048576 bytes` | Body | Supply nonempty UTF-8 of at most 1 MiB |
| `duplicate evidence hash`, `at most 1024 evidence hashes` | Evidence | Pass each hash once |
| `refusing to write into non-empty`, `exists and is not a directory` | `--out` | Use a new directory |
| `does not hash to the body the envelope signs`, `does not match envelope.bin and body.bin`, `envelope.bin:` | `DIR` changed after `genesis`, or a build with another pinned taxonomy | Run `genesis` again into a new directory and review it |
| `node reports ledger`, `posture is frozen`, `semantic readiness is` | Node not writable in v1 mode | Wait for the node operator; no flag overrides this |
| `refusing to submit; nothing was written` | A trust check failed; the lines name which | Use the right node, instance, key or build |
| `node did not admit the envelope as valid`, `node acknowledged a different envelope` | HTTP 202 pending or 422 invalid; or an outcome naming another event or digest | Read the state and reason; investigate the node |
| `readback:` | The node does not serve what was signed | Investigate; rerun `submit` once fixed |
