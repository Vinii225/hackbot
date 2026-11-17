# Skill: HTTP Verb Tampering

Operational playbook. Confirm whether an access control enforced on one HTTP method is
skipped for another. Non-destructive: send an empty-bodied alternate verb; never submit a
real state-changing payload.

## Trigger conditions
IF a hypothesis has class `VERB-TAMPER` AND an endpoint is access-controlled.

## Procedure
1. Request the endpoint with GET (expected to be denied).
2. Request the same path with POST (empty body).

## Confirmation criteria
- GET is denied (401/403) but POST returns 200 — the control is scoped to one verb.

## False-positive criteria
- The authorization result is the same across methods.

## Evidence requirements
- `get.*` and `post.*`.

## Output
- Finding JSON with `class: "VERB-TAMPER"`, `status`, `endpoint`, the bypassing method, `evidence`.
