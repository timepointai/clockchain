# Mission brief template

Fill this in rather than writing a brief from scratch. The structure is what stops a session
degrading into reactive firefighting; rediscovering it costs days.

**Two rules for whoever writes the brief:**
1. **Every Definition-of-Done item must be verifiable by a command.** If you cannot write the
   command that proves it, the item is not done-able — it is a wish.
2. **Anything "good to do" that is not on the DoD list goes to the backlog in one line, and is
   not touched.** Scope creep is how a five-move job becomes a campaign.

---

## Ground truth

> Numbers here must be **live-verifiable**, each with the command that reads it.
> **If any number fails to match live, stop and report the delta before proceeding.**

This section is the tripwire, and it is not decoration. A brief was once written from a
10-day-old transcript: it described a service, a workspace and database tables that had all been
deleted days earlier. Executing it would have meant deleting things twice, rotating credentials
on services that no longer existed, and publishing stale counts to a public site. Refusing it
was the highest-value action in that session.

Stale ground truth is more dangerous than absent ground truth, because it wears trust.

```
<fact>          <value>          <command that verifies it>
```

## Definition of Done

Numbered, measurable, each independently checkable. For each item state the command that proves
it green. Order by priority and note which items gate which.

```
1. <what> — verified by: <command> — gates: <items>
```

## Operating rules

Reference [`ops/README.md`](README.md). **Do not restate them** — a copy drifts from the
original and then nobody knows which governs.

Name only the deviations this mission needs, and why.

## Execution order

Phases with explicit gates. For each: what changes, expected before/after counts, and what must
be true to proceed. Mark the irreversible steps — deletions, spend, public surfaces, credential
rotation — as human-approval gates.

State which approvals are pre-granted and which are not, so the agent does not stall on an
approval it already has, or assume one it does not.

## Out of scope

Name it explicitly, log it to the backlog, do not touch it. "Not mentioned" is not the same as
"out of scope" — an agent will reasonably infer that unmentioned adjacent work is invited.

---

## Reporting shape

Per phase: ≤10 lines. What changed, counts before/after, anomalies, next gate. No recaps, no
restating the plan, no tables of things that did not change.

Final report: system state · open items with an owner each · where everything lives.

Lead with the outcome, then verified facts **with their evidence** — the query, the URL, the
row. Then the cost, then what is left, then the human's decisions isolated at the end. Then stop.
No promises about work not done.
