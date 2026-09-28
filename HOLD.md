# Standing owner hold

Read this file before release, publication, generation, or fixture work. These
constraints remain active until the owner explicitly changes them.

- No deployment or production writes.
- No historical or image generation, model calls, new model attempts, or retries.
- The private inaugural fixture is frozen: preserve its files, receipts, bindings,
  image bytes and hashes. Do not replace its sources or publish any subset.
- Excluded private images do not imply a signed absence decision.
- Passing tests or a software merge do not authorize release or publication.

## PR #5 merge record — 2026-09-28

PR #5 merged under the owner's independent HTTP policy decision and explicit
merge authorization, conditional on green CI. Deployment, generation and
publication remain held. [Issue #6](https://github.com/timepointai/clockchain/issues/6)
records gates that block the first production entry, not this software merge.

Local synthetic tests, scoped software changes and review evidence are permitted
when requested. They must not use the inaugural fixture as test content. A request
for a recommendation does not authorize implementing the recommended design.

Keep these constraints here; do not repeat the checklist in routine turn updates.
Report a violation, changed instruction or concrete blocker when relevant.
