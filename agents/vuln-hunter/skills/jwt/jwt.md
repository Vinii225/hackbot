# Skill: JWT alg:none Signature Bypass

Operational playbook. Confirm whether an endpoint accepts an unsigned JWT (`alg: none`),
letting an attacker forge any identity without the signing key. Non-destructive: one forged
token asserting a privileged user; read only whether it is accepted.

## Trigger conditions
IF a hypothesis has class `JWT`
AND an endpoint authenticates via a bearer token (jwt, whoami, token, session-info).

## Required inputs
- `endpoint`, `method`.

## Procedure
1. Build a token with header `{"alg":"none","typ":"JWT"}`, payload claiming a privileged
   user (e.g. `administrator`), and an empty signature. Send it as `Authorization: Bearer`.
   → `alg-none.*`

## Confirmation criteria
- The response is 200 and reflects the forged identity — the server trusted an unsigned
  token.

## False-positive criteria
- The unsigned token is rejected (401/403).

## Evidence requirements
- `alg-none.*` showing the forged token and the accepting response.

## Safety
- One forged read-only request. Do NOT act on the forged session or escalate further;
  acceptance is the proof.

## Output
- Finding JSON (`contracts/finding.schema.md`) with `class: "JWT"`, `status`, `endpoint`,
  `method`, the confirming `payload`, and `evidence` file refs.
