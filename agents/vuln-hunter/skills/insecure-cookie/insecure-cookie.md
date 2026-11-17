# Skill: Insecure Cookie

Operational playbook. Confirm whether a session cookie is issued without the HttpOnly and
Secure flags, exposing it to script theft or plaintext interception. Non-destructive: a
single read of the response headers.

## Trigger conditions
IF a hypothesis has class `INSECURE-COOKIE` AND an endpoint issues a Set-Cookie header.

## Procedure
1. GET the endpoint and read the `Set-Cookie` response header.

## Confirmation criteria
- A cookie is set lacking `HttpOnly` and/or `Secure`.

## False-positive criteria
- The cookie carries both `HttpOnly` and `Secure`.

## Evidence requirements
- `set-cookie.*` capturing the raw header.

## Output
- Finding JSON with `class: "INSECURE-COOKIE"`, `status`, `endpoint`, the missing flags, `evidence`.
