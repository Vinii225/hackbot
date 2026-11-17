# Skill: Cross-Site Request Forgery (CSRF)

Operational playbook. Confirm whether a state-changing request is accepted without an
unpredictable anti-CSRF token, letting another site forge it with the victim's cookies.
Non-destructive: a single benign change (a marker email); never perform a damaging or
irreversible action to "prove" it.

## Trigger conditions
IF a hypothesis has class `CSRF`
AND an endpoint is a state-changing POST (change, update, edit, delete, add, transfer,
settings, profile).

## Required inputs
- `endpoint`, `method` (POST), the state-changing `parameter`.

## Procedure
1. Submit the state change with the functional parameter only and **no CSRF token**.
   → `no-token.*`

## Confirmation criteria
- The change is accepted (2xx reflecting the submitted value) although no unpredictable
  token was sent — the request is forgeable cross-site.

## False-positive criteria
- The request is rejected for a missing/invalid token (4xx, or an error naming csrf/token).

## Evidence requirements
- The `no-token.*` request/response showing the change accepted without a token.

## Safety
- Make one benign, reversible change. Do NOT delete data or move funds; acceptance without a
  token is the proof, not the damage.

## Output
- Finding JSON (`contracts/finding.schema.md`) with `class: "CSRF"`, `status`, `endpoint`,
  `method`, the confirming `payload`, and `evidence` file refs.
