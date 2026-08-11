# Security Policy

AADA is a research/educational project, not a production security product —
worth keeping in mind when reading this. The remediation backends
(`SimulatedFirewall`, in-memory notifier/ticketing) are safe simulations by
design; nothing here talks to a real firewall or account system unless you
wire one in yourself, and if you do, keep it behind the approval workflow.

## Supported versions

There are no tagged releases yet — `main` is the only supported branch.
Security fixes land there.

## Reporting a vulnerability

Open a [GitHub issue](https://github.com/pranjalm37/autonomous-defense-agent/issues)
describing the problem. For most things in a project like this (a detection
rule that misses an obvious case, a guardrail that doesn't hold, an auth
check that's missing) a public issue is fine.

If it's something that shouldn't be public before a fix ships — a real
credential leak, an auth bypass, anything exploitable against someone
actually running this — open the issue anyway but leave out exploit
specifics, and say so in the title so it gets picked up quickly.

## Scope notes

A few things that are deliberate, not vulnerabilities:

- The system runs fully offline by default (deterministic local providers
  for the LLM, embeddings, and threat feeds) — this is by design, not a
  missing integration.
- `.env.example` ships with placeholder values. Real secrets belong in
  `.env`, which is git-ignored — never open a PR that adds one.
- The response engine's guardrails (refusing to block internal IPs or
  disable protected accounts) are a floor, not a complete authorization
  model. Don't point this at production infrastructure without review.
