# Skill: Host Header Injection

Operational playbook. Confirm whether the application builds absolute URLs (password-reset
links, redirects, cache keys) from the attacker-controlled `Host` header. Non-destructive:
one request with a marker Host; read only whether it is reflected.

## Trigger conditions
IF a hypothesis has class `HOST-HEADER`
AND an endpoint plausibly emits an absolute link (reset, forgot, verify, confirm, invite,
activate, recover).

## Required inputs
- `endpoint`, `method`.

## Procedure
1. Request the endpoint normally (real Host). → `control-host.*`
2. Request it again with `Host: evil-<rand>.example`. → `inject-host.*`

## Confirmation criteria
- The marker host appears in the injected response (e.g. inside a generated link) and not
  in the control — a reset/verify link can be pointed at an attacker host.

## False-positive criteria
- The response uses a fixed canonical host regardless of the request Host header.

## Evidence requirements
- `control-host.*` and `inject-host.*`, plus the reflected marker.

## Safety
- One probe. Do NOT trigger real password-reset emails or poison shared caches; reflection
  into the response body is proof.

## Output
- Finding JSON (`contracts/finding.schema.md`) with `class: "HOST-HEADER"`, `status`,
  `endpoint`, `method`, the confirming `payload` (the Host), and `evidence` file refs.
