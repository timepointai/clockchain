# Standing owner hold

Read this file before release, publication, generation, or fixture work. These
constraints remain active until the owner explicitly changes them.

- No deployment or production writes.
- No historical or image generation, model calls, new model attempts, or retries.
- The private inaugural fixture is frozen: preserve its files, receipts, bindings,
  image bytes and hashes. Do not replace its sources or publish any subset.
- Excluded private images do not imply a signed absence decision.
- PR #5 requires independent review. The implementing agent must not approve or
  merge it. Passing tests do not authorize release or publication.

Local synthetic tests, scoped software changes and review evidence are permitted
when requested. They must not use the inaugural fixture as test content. A request
for a recommendation does not authorize implementing the recommended design.

Keep these constraints here; do not repeat the checklist in routine turn updates.
Report a violation, changed instruction or concrete blocker when relevant.
