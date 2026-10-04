# Keys: cold root, hot key

This runbook covers the `cc-publisher v1` authority commands: `grants`,
`delegate` and `revoke`, and `submit` for their output. They let the owner keep
the root (curator) seed offline and do routine signing with a delegated hot key.
Nothing in this page has been run against production. Every command below is an
owner action, run from the owner's workstation or the owner's offline machine.
Generating, holding and using the root key stays with the owner alone
([HOLD.md](../HOLD.md)).

The commands build the Stage (b) `Delegate` and `Revoke` payloads
([STAGE-B.md](design/STAGE-B.md)) exactly as fold version 1 admits them. They
change nothing in admission or projection. The fold manifest's `authority.*`
lines are the rules; this page restates them where a step depends on them.

## What a grant can and cannot do in fold v1

- **Grants are per subject.** Each Genesis creates its own root grant,
  `sha256(cc.root-grant.v1|genesis)` (`authority.root_grant`), held by the
  Genesis author. A `Delegate` gives a key authority over that one subject.
  Each subject needs its own Delegate.
- **What a grant authorizes.** A grant authorizes the subject-chain events
  signed under it: `Correction`, `Resolve`, `Delegate` (to a fresh key) and
  `Revoke` (of a grant in its scope). The node checks that the grant is
  active in the event's parent cone and held by the author.
- **What a grant does not authorize.**
  - *Edges and attestations.* They do not use grants at all. Support counts an
    edge only when its author and both endpoint Genesis authors are curators
    (`support.trust`), so a hot key's edges never count as support.
  - *New subjects.* A Genesis needs no grant, but a subject counts for support
    only when its Genesis author is a curator. With the root as the only
    curator, every new subject needs the root key for its Genesis, and then a
    Delegate if a hot key is to correct it.
  - *The curator set.* The curator set is part of the bound rule identity. A
    bound fold v1 store refuses a different identity, so a hot key cannot be
    made a curator on the running store. Changing the curator set is an owner
    decision outside this tooling.
- **Delegate.** The grantee must be a valid Ed25519 key that has never held a
  grant on the subject, active or not (`authority.delegate_key`). A Delegate
  never carries an asserted time.
- **Revoke scope.** A key may revoke only an active grant that is a strict
  issuer descendant of its own grant: something it, or a key below it,
  delegated. The one exception is the root revoking its own root grant
  (`authority.revoke_scope=strict_issuer_descendant_or_root_self`). A hot key
  cannot revoke itself, its issuer or a sibling.
- **Cascade.** The cascade flag is signed into the Revoke
  (`authority.cascade=signed_bool_target_subtree`).
  - `--no-cascade` tombstones the target only. Grants the target issued in the
    revoke's acknowledged past stay active.
  - `--cascade` tombstones the target's whole provenance subtree, including
    grants learned later.
  - Grants outside the subtree are never affected.
- **What survives a revoke.** Acts under a covered grant survive only if they
  are in the revoke's reflexive acknowledged past: its parent and that
  parent's ancestors. Acts outside it become `revoked_concurrent`, and events
  built on them become `revoked_ancestor` (`visibility.suppressed`). Which
  acts survive therefore depends on the parent the Revoke extends. The
  compromise playbook below uses this.
- **Retention.** The node keeps every envelope it is sent, including invalid
  ones (they enter the corpus digest as retained candidates). So the publisher
  checks first and refuses before posting. `--allow-untrusted` posts anyway.

## Files

| File | Holds | Where |
|---|---|---|
| `root.seed` | Root (curator) seed | Offline machine and offline backups only |
| `hot.seed` | Hot-key seed | Owner's workstation, mode 0600 |
| `grants.json` | A subject's grants and events as one node served them, plus that node's URL | Private; not a secret, but it names the node |
| `delegate/`, `revoke/` | `envelope.bin`, `preview.json`, and after submit `receipt.json` | Private working directories |

Seeds follow the key-file rules in [PUBLISHER-V1.md](PUBLISHER-V1.md#key-files).
`delegate` and `revoke` never contact a node: copy `grants.json` to the offline
machine, and copy the output directory back. Removable media is fine; neither
file is secret. Never put a seed, a grants file or a receipt in this repository.

## Commands

### grants

```sh
cc-publisher v1 grants --node URL --subject SUBJECT_HEX [--out grants.json]
```

Read-only. It sends only `GET /health` and `GET /v1/snapshot`. It needs
`CC_NODE_READ_KEY`, or `CC_NODE_API_KEY` when that is unset. It refuses a node
whose ledger is not `v1` or whose fold differs from this build.

It prints the subject's authority as JSON (schema `cc.publisher.v1.grants`),
and with `--out` it also writes that JSON to a new file (an existing path is
refused). The JSON holds:

- `node_health`, `corpus_digest` and `commitment`;
- the subject, its key, its state, `frozen` and its frontier;
- `root`: the root grant, its holder, and whether the holder is a curator;
- `active`: the active grant ids;
- `grants`: every grant on the subject, with `status`, `holder`, `issuer`,
  `issued_by_event`, `depth` and `lineage` from the root down. `status` is one
  of `active`, `tombstoned` or `canceled`;
- `events`: every subject event, with kind, author, signing grant, parents,
  projection state and suppression reason.

These values are the node's own authority derivation; the publisher does not
recompute them. The whole snapshot is read, so the answer is bounded by the
client's 16 MiB response limit.

### delegate

```sh
cc-publisher v1 delegate --key SIGNER.seed --grants grants.json \
  --grantee GRANTEE_PUBKEY_HEX --rationale "TEXT" \
  --evidence SHA256_HEX [--evidence ...] --out DIR
```

Offline. It loads and checks the grants file, then signs a Delegate on the
subject's sole head, under the signer's grant, to the grantee. It refuses, and
writes nothing, when:

- the grants file is not one `grants` wrote, is internally inconsistent
  (lineages, the `active` list, the root grant), or comes from a node whose
  fold differs;
- the key holds no active grant on the subject, or holds more than one (the
  error names a tombstoned or canceled grant it used to hold);
- the subject is frozen or has more than one head (that needs a `Resolve`,
  which this tooling does not build);
- the grantee is not a valid Ed25519 public key, or has ever held a grant on
  the subject;
- the rationale is empty, over 1024 bytes, has control or invisible
  characters, or has outer whitespace; or no `--evidence` is given;
- `--out` exists and is not empty.

`DIR` gets `envelope.bin` and `preview.json`. The preview (schema
`cc.publisher.v1.authority-preview`) is a pure function of the envelope. It
includes the signer, signing grant, parent and grantee. It also includes
`new_grant`: the Delegate's event id, which is the new grant's id. Stdout
repeats this as a review summary.

### revoke

```sh
cc-publisher v1 revoke --key SIGNER.seed --grants grants.json \
  --target GRANT_HEX (--cascade | --no-cascade) [--relinquish-root] \
  [--parent EVENT_HEX] --rationale "TEXT" --evidence SHA256_HEX --out DIR
```

Offline. Exactly one of `--cascade` and `--no-cascade` is required. Neither, or
both, is a parser error (exit 2). The grants-file, key, rationale, evidence and
output checks are those of `delegate`. In addition it refuses when:

- the target is not an active grant on the subject;
- the target is not a strict issuer descendant of the signer's grant;
- the target is the root grant and the signer is the root, without
  `--relinquish-root` (relinquishing is irreversible; this runbook never
  calls for it);
- `--relinquish-root` is passed for any other target;
- `--parent` is not a valid event of the subject. Without `--parent`, the
  Revoke extends the sole head.

The summary states how many active grants below the target the cascade choice
revokes or leaves, and lists any events outside the revoke's past.

### submit

```sh
cc-publisher v1 submit --node URL --dir DIR [--allow-untrusted]
```

`submit` sees that `DIR/envelope.bin` is a Delegate or Revoke and takes the
authority path. It needs `CC_NODE_API_KEY`.

1. Reload `DIR`. The envelope must decode, verify, and pass the structural
   checks: one parent, the subject header, no asserted time, and a decision
   that restates the payload. `preview.json` must equal the recomputed
   preview.
2. `GET /health`. Refuse unless `ledger` is `v1`, `posture` is not `frozen` and
   `semantic` is `ready`.
3. `GET /v1/snapshot` for the subject's current grants, events and frontier.
4. If the node already retains this event, report it as `already_admitted`,
   apply only the instance, fold and filter checks, and do not post it again.
   Otherwise run the trust checks, one line per failure:
   - **instance:** the instance matches;
   - **fold:** the fold matches this build;
   - **filter:** `filter_version` is consistent;
   - **root holder:** the subject's root holder is a curator;
   - **signing grant:** the grant is active and held by the author. This
     replaces the Genesis "author is a curator" check, because a delegated
     key is not a curator and legitimately signs;
   - **parent:** the parent is the subject's sole head;
   - **operation:** for a Delegate, the grantee is fresh; for a Revoke, the
     target is active and in the signing grant's scope.

   Failures are refused under `refusing to submit; nothing was written`.
   `--allow-untrusted` overrides them all, prints each override to stderr, and
   records it in the receipt. The node then decides, and keeps the envelope
   even if it is invalid.
5. `POST /v1/candidates`. It requires HTTP 201, state `valid`, this event id,
   and the envelope's SHA-256.
6. Read back `GET /v1/snapshot`. The event must be valid and unsuppressed.
   - A Delegate's grant must be active and held by the grantee under the
     signing grant.
   - A Revoke's target must be tombstoned. With cascade, every grant below
     the target must be tombstoned too.
7. Write `DIR/receipt.json` (schema `cc.publisher.v1.authority-receipt`) if it
   does not exist. Stdout is the receipt; stderr has the `envelope`,
   `readback` and `receipt` lines.

## The hot-key ceremony (once per subject)

Run on the workstation unless marked **offline**. Placeholders are in capitals.
`SUBJECT_HEX` is the subject's Genesis event id.

1. Make the hot key on the workstation and note its public key:

   ```sh
   cc-publisher v1 keygen --out hot.seed
   ```

2. Read the subject's grants (read-only):

   ```sh
   read -r CC_NODE_READ_KEY < read.token; export CC_NODE_READ_KEY
   cc-publisher v1 grants --node https://NODE --subject SUBJECT_HEX --out grants.json
   ```

   Check `root.holder` is the root public key, `root.holder_is_curator` is
   `true`, `active` lists only the root grant, and `frontier` has one event.
3. Copy `grants.json` to the offline machine.
4. **Offline:** sign the Delegate with the root, then review the summary and
   `delegate/preview.json`. Check that `grantee` is the hot public key from
   step 1 and that `signer` is the root:

   ```sh
   cc-publisher v1 delegate --key root.seed --grants grants.json \
     --grantee HOT_PUBKEY_HEX --rationale "Hot key for routine corrections" \
     --evidence SHA256_OF_A_CEREMONY_NOTE --out delegate/
   ```

5. Copy `delegate/` back. Do not copy `root.seed`.
6. Submit:

   ```sh
   read -r CC_NODE_API_KEY < write.token; export CC_NODE_API_KEY
   cc-publisher v1 submit --node https://NODE --dir delegate/
   ```

7. Confirm with `grants`. The new grant (`new_grant` in the preview) should be
   `active`, its holder the hot key and its issuer the root grant.
8. **Offline:** the root seed goes back to cold storage. It is needed again
   only for:
   - a new subject's Genesis and its Delegate;
   - rotation;
   - the compromise playbook.

## Routine signing with the hot key

- Check before signing: `cc-publisher v1 grants ... --out grants.json`, then
  confirm the hot key's grant is `active` and the subject has one head.
- Sub-delegation: the hot key may delegate to another fresh key. It can later
  revoke that key, because the key is its strict descendant.

  ```sh
  cc-publisher v1 delegate --key hot.seed --grants grants.json \
    --grantee OTHER_PUBKEY_HEX --rationale "TEXT" --evidence SHA256_HEX --out sub/
  cc-publisher v1 submit --node https://NODE --dir sub/
  ```

- Corrections signed with the hot key are admitted on a delegated subject. The
  real-node test `delegated_key_corrects_and_is_refused_after_revoke` shows
  this. This change does not add a `correction` command; the publisher's
  correction tooling is Stage (g) G3 (`docs/AUTHORING-V1.md` once merged).
  Whatever builds the Correction, it signs under the hot key's grant id (the
  Delegate event id) and extends the sole head.
- The hot key cannot do any of these; each needs the root:
  - create curator-trusted subjects;
  - author edges that count as support;
  - change the curator set.

## Rotation (planned, nothing compromised)

The root is needed, and each step needs a fresh grants file, because a signed
event always extends the sole head the file names.

1. `keygen --out hot2.seed` on the workstation.
2. Run `grants --out g1.json` and copy it offline. **Offline:**
   `delegate --key root.seed --grants g1.json --grantee HOT2_PUBKEY_HEX ... --out d2/`.
   Copy `d2/` back and `submit` it.
3. Run `grants --out g2.json` and copy it offline. **Offline:**
   `revoke --key root.seed --grants g2.json --target OLD_HOT_GRANT_HEX --no-cascade ... --out r/`.
   Use `--cascade` instead if the old key delegated sub-keys that should go
   too. Copy `r/` back and `submit` it.
4. Run `grants`. The old grant should be `tombstoned` and the new one `active`.
   The old key's past corrections stay, because they are in the revoke's past.
   Then destroy `hot.seed`.

Delegating before revoking means the subject is never without a working hot
key. Repeat for every subject the old key held.

## Compromise playbook (hot key leaked)

A revoke on the current head acknowledges everything before it, so hostile acts
already admitted would survive. The playbook revokes with cascade on the **last
trusted event** instead. The real-node test
`compromise_revoke_on_the_last_good_parent_suppresses_later_acts` shows both
outcomes.

1. Stop using the hot key and keep a copy of what you know of the leak. Do not
   delete anything on the node; the node cannot delete.
2. Read the subject's state (read-only):

   ```sh
   cc-publisher v1 grants --node https://NODE --subject SUBJECT_HEX --out g.json
   ```

   In `events`, find the acts under the compromised grant, or any grant whose
   `lineage` contains it, that you did not make. Pick `LAST_GOOD_EVENT_HEX`:
   the latest subject event before the first hostile act. If there is no
   hostile act yet, omit `--parent`.
3. Copy `g.json` offline. **Offline:**

   ```sh
   cc-publisher v1 revoke --key root.seed --grants g.json \
     --target HOT_GRANT_HEX --cascade --parent LAST_GOOD_EVENT_HEX \
     --rationale "Hot key compromised" --evidence SHA256_OF_INCIDENT_NOTE \
     --out revoke/
   ```

   The summary lists the events outside the revoke's past.
4. Copy `revoke/` back and run `submit` without overrides. It refuses because
   the parent is not the sole head, and lists each event outside the revoke's
   past. Check that the list is the hostile acts and anything built on them.
   On a linear chain, every later event descends from the first hostile act,
   so your own later acts are on the list too and must be re-authored. Then:

   ```sh
   cc-publisher v1 submit --node https://NODE --dir revoke/ --allow-untrusted
   ```

   `--allow-untrusted` overrides every failed check, not only the parent one.
   Read each `warning:` line before you trust the result. Only the parent line
   should appear.
5. Verify the result:
   - `grants`: the compromised grant and every grant below it are
     `tombstoned`, and the revoke is the only head;
   - `cc-publisher v1 verify --subject SUBJECT_HEX`: the current revision is
     the last trusted one;
   - every grant you did not mean to keep shows `tombstoned`. Revoke any that
     does not.
6. Run the hot-key ceremony again with a fresh key. Repeat steps 2 to 5 for
   every subject the leaked key held.
7. A revoke does not remove edges or attestations, which are not grant-based.
   A hot key's edges never counted as support (it is not a curator), but
   review any it authored.

## What a lost root means

- **Root seed lost, not leaked:**
  - no new curator-trusted subject can be created, because the curator set is
    fixed by the bound rule identity;
  - no grant the root issued can be revoked or replaced. A hot key can still
    revoke its own sub-delegates;
  - existing hot keys keep correcting their subjects;
  - if a hot key is then lost or leaked, its subject has no recovery in fold
    v1.

  Keep at least two independent offline copies of `root.seed`. Check each
  copy with `cc-publisher v1 pubkey --key COPY` against the curator key in
  `/health`.
- **Root seed leaked.** The holder can revoke every delegate, correct every
  subject it roots, and relinquish them. Fold v1 has no authority above the
  root, so nothing in it recovers a compromised root
  ([STAGE-B.md](design/STAGE-B.md)). Recovery means a new curator set and so
  a new rule identity, which is an owner decision outside this runbook.
- **Hot key lost, not leaked:** run rotation (the root delegates a new key,
  then revokes the old one with `--no-cascade`).

## Where this is tested

All tests are in `crates/cc-publisher/tests/v1_authority.rs`. They run against
the real v1 serving router over real PostgreSQL, with synthetic keys only.

| Test | Shows |
|---|---|
| `delegated_key_corrects_and_is_refused_after_revoke` | A hot key's Correction is admitted. After a non-cascade revoke, the hot key is refused offline, by `submit` and by the node (`parent_authority`). Its acknowledged sub-delegate still corrects. |
| `cascade_revokes_the_whole_subtree_and_nothing_else` | Cascade tombstones the target and its descendants. An independent sibling grant survives. |
| `issuer_scope_is_enforced_offline_by_submit_and_by_the_node` | Upward, sideways and self revokes are refused offline, by `submit`, and by the node (`revocation_scope`). A non-root issuer may revoke its own delegate. |
| `compromise_revoke_on_the_last_good_parent_suppresses_later_acts` | The playbook restores the last trusted revision. A revoke on the head keeps the hostile one. |
| `cli_grants_delegate_revoke_and_submit` | The CLI round trip. Cascade must be explicit, an ungranted key writes nothing, and tampered grants files and previews are refused. |
