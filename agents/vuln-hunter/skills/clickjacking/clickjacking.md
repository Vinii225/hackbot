# Skill: Clickjacking (Missing Frame Protection)

Operational playbook. Confirm whether a sensitive HTML page can be framed by any site
because it sets neither `X-Frame-Options` nor a CSP `frame-ancestors` directive. Fully
passive: one GET; read only the response headers.

## Trigger conditions
IF a hypothesis has class `CLICKJACKING`
AND the endpoint serves a sensitive HTML page (panel, dashboard, account, settings,
profile).

## Required inputs
- `endpoint`, `method` (GET).

## Procedure
1. GET the page and inspect the response headers. → `frame-headers.*`

## Confirmation criteria
- A 200 HTML response with no `X-Frame-Options` header and no CSP `frame-ancestors`
  directive — the page can be loaded in an attacker's iframe and overlaid.

## False-positive criteria
- `X-Frame-Options` is present, or CSP includes `frame-ancestors`.

## Evidence requirements
- `frame-headers.*` showing the response headers (or their absence).

## Safety
- Read-only header inspection. No framing PoC page needs to be hosted; the missing headers
  are the finding.

## Output
- Finding JSON (`contracts/finding.schema.md`) with `class: "CLICKJACKING"`, `status`,
  `endpoint`, `method`, and `evidence` file refs.
