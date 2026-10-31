# Skill: Reflected XSS (Cross-Site Scripting)

Operational playbook. Confirm whether a parameter is reflected into an HTML response
without encoding, so attacker-controlled markup reaches the browser. Non-destructive:
prove reflection with a harmless unique marker; do not deliver a real payload to anyone.

## Trigger conditions
IF a hypothesis has class `XSS`
AND a parameter is echoed back into a response (search term, message, name, query, etc.).

## Required inputs
- `endpoint`, `method`, the reflected `parameter`.

## Procedure
THEN send the parameter with a plain unique token (no metacharacters) to confirm the
reflection point and capture a control. → `control-plain.request/response.http`.
THEN send the parameter with the token wrapped in angle brackets: `<TOKEN>`.
→ `inject-xss.request/response.http`.
THEN inspect the response:
  - is the `Content-Type` HTML?
  - does the raw `<TOKEN>` appear verbatim (brackets intact), or only encoded
    (`&lt;TOKEN&gt;`)?

## Decision rules
- Raw `<TOKEN>` present in an HTML response → the markup was not encoded → candidate
  confirmation (it would run as markup/script in a browser).
- Only the encoded form present → the app escapes output → false positive.

## Confirmation criteria (ALL must hold)
- Response `Content-Type` is `text/html`.
- The injected `<TOKEN>` appears unencoded (angle brackets intact) in the body.
- The token was genuinely reflected from the request (present in the control too).

## False-positive criteria (ANY)
- The reflected value is HTML-entity encoded (`&lt;`/`&gt;`) or otherwise sanitized.
- The response is not HTML (e.g. JSON with correct content type).
- The parameter is not reflected at all.

## Evidence requirements
- `control-plain.request.http` / `.response.http`.
- `inject-xss.request.http` / `.response.http`.
- Note the exact reflected marker and whether it was encoded.

## Output
- Finding JSON (`contracts/finding.schema.md`) with:
  `class: "XSS"`, `status: confirmed|unconfirmed|false-positive`,
  `endpoint`, `method`, `parameter`, the confirming `payload`, and `evidence` file refs.
