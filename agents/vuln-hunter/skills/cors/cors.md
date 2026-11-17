# Skill: CORS Misconfiguration

Operational playbook. Confirm whether an endpoint trusts an arbitrary `Origin`, letting any
site read its (possibly authenticated) response. Non-destructive: a single probe request
with a crafted `Origin` header; read only the CORS response headers.

## Trigger conditions
IF a hypothesis has class `CORS`
AND the endpoint looks like an API that may serve cross-origin reads.

## Required inputs
- `endpoint`, `method`.

## Procedure
1. Send the request with `Origin: https://evil-<rand>.example`. → `cors-probe.*`
2. Read `Access-Control-Allow-Origin` (ACAO) and `Access-Control-Allow-Credentials` (ACAC).

## Confirmation criteria
- ACAO echoes the attacker Origin (origin reflection), OR ACAO is `*` together with
  `ACAC: true`. With `ACAC: true` the impact is authenticated cross-origin reads (high);
  without credentials it still exposes the response body (medium).

## False-positive criteria
- ACAO is a fixed, allowlisted origin (not the attacker's) — cross-origin access is
  constrained.

## Evidence requirements
- The `cors-probe.*` request/response showing the sent `Origin` and the returned ACAO/ACAC.

## Safety
- One read-only probe. Do NOT replay stolen cookies or exfiltrate data; the reflected
  header is proof enough.

## Output
- Finding JSON (`contracts/finding.schema.md`) with `class: "CORS"`, `status`, `endpoint`,
  `method`, the confirming `payload` (the Origin), and `evidence` file refs.
