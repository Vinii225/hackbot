# Skill: Open Redirect

Operational playbook. Confirm whether a destination parameter can send the browser to an
attacker-controlled host. Non-destructive and scope-safe: the redirect is **never
followed**, only the `Location` header is read, and the marker host (`.example`, reserved)
is never contacted.

## Trigger conditions
IF a hypothesis has class `OPEN-REDIRECT`
AND a parameter plausibly sets a redirect/return destination (next, redirect, return,
returnUrl, dest, destination, continue, goto, callback, to).

## Required inputs
- `endpoint`, `method`, the `parameter`.

## Procedure
1. Send the destination parameter set to an off-site marker, with redirect following
   **disabled**: `https://evil-<rand>.example/hb`, then the scheme-relative
   `//evil-<rand>.example/hb` (the common filter bypass). → `redirect-probe-*.*`
2. Read the response status and `Location` header without following the redirect.

## Confirmation criteria
- The response is a 3xx and the `Location` host equals the marker host — the app redirects
  off-site to a destination the attacker fully controls.

## False-positive criteria
- A redirect occurs but `Location` stays same-site (relative path, or the app's own host) —
  the destination is validated or confined.

## Evidence requirements
- The `redirect-probe-*.*` responses and the confirming `Location` value and status.

## Safety
- Do NOT follow the redirect or request the marker host. One off-site `Location` is proof.

## Output
- Finding JSON (`contracts/finding.schema.md`) with `class: "OPEN-REDIRECT"`, `status`,
  `endpoint`, `method`, `parameter`, the confirming `payload`, and `evidence` file refs.
