# Skill: XML External Entity (XXE) Injection

Operational playbook. Confirm whether an XML parser resolves external entities, pulling a
local file into the response. Non-destructive and scope-safe: reference one benign local
file (`/etc/passwd`); never read secrets, SSRF via entities, or trigger entity expansion
(billion-laughs) DoS.

## Trigger conditions
IF a hypothesis has class `XXE`
AND an endpoint parses an uploaded/posted XML document (import, upload, parse, soap, feed).

## Required inputs
- `endpoint`, `method` (POST).

## Procedure
1. Send a benign control document with no entity. → `control-noentity.*`
2. Send the same document with a DOCTYPE declaring
   `<!ENTITY x SYSTEM "file:///etc/passwd">` and a body that references `&x;`.
   → `inject-xxe.*`

## Confirmation criteria
- The injection response contains `/etc/passwd` content (a line matching `root:...:0:0:`)
  that the entity-free control does not.

## False-positive criteria
- The entity reference comes back unexpanded (e.g. literal `&x;`) — external entities are
  disabled.

## Evidence requirements
- `control-noentity.*` and the confirming `inject-xxe.*`, plus the leaked line.

## Safety
- One read-only file reference. Do NOT chain to internal SSRF, parameter entities, or
  recursive entity expansion. A single resolved file is proof.

## Output
- Finding JSON (`contracts/finding.schema.md`) with `class: "XXE"`, `status`, `endpoint`,
  `method`, the confirming `payload`, and `evidence` file refs.
