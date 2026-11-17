# Skill: Server-Side Request Forgery (SSRF)

Operational playbook. Confirm whether a parameter makes the server fetch a URL the attacker
controls, reaching resources the server can see but the client cannot. Non-destructive and
scope-safe: our client only ever requests the in-scope target; the internal address is a
string in the parameter, never contacted by us.

## Trigger conditions
IF a hypothesis has class `SSRF`
AND a parameter plausibly carries a URL the server dereferences (url, uri, link, fetch,
feed, webhook, proxy, image, src, domain, callback).

## Required inputs
- `endpoint`, `method`, the `parameter`.

## Procedure
1. Send a benign external control (`https://example.com/`). → `control-external.*`
2. Send the cloud instance-metadata address
   (`http://169.254.169.254/latest/meta-data/`). → `probe-metadata.*`
3. Compare: internal-only content returned for the metadata probe, but not the control,
   means the server made the request on your behalf.

## Confirmation criteria
- The metadata probe response carries distinctive internal content
  (`iam/security-credentials`, `ami-id`, `instance-id`) absent from the external control.

## False-positive criteria
- The internal/link-local address is blocked (4xx) while an external URL is allowed — an
  SSRF guard/allowlist is in place.

## Evidence requirements
- `control-external.*` and `probe-metadata.*`, plus the internal markers observed.

## Safety
- Read-only confirmation against a benign metadata path. Do NOT pivot to internal services,
  exfiltrate credentials, or chain to further internal requests. One leaked internal
  response is proof.

## Output
- Finding JSON (`contracts/finding.schema.md`) with `class: "SSRF"`, `status`, `endpoint`,
  `method`, `parameter`, the confirming `payload`, and `evidence` file refs.
