# Skill: CRLF Injection / HTTP Response Splitting

Operational playbook. Confirm whether a value reflected into a response header is not
stripped of CR/LF, letting an attacker inject a header. Non-destructive: inject one benign
marker header; never split a full second response or poison a shared cache.

## Trigger conditions
IF a hypothesis has class `CRLF` AND an endpoint reflects input into a response header.

## Procedure
1. Submit a value containing `\r\n` followed by `X-Hbcrlf: <marker>`.

## Confirmation criteria
- The response carries the injected `X-Hbcrlf` header (the CR/LF was honored).

## False-positive criteria
- CR/LF is stripped; no extra header appears.

## Evidence requirements
- `inject-crlf.*` capturing the response headers.

## Output
- Finding JSON with `class: "CRLF"`, `status`, `endpoint`, `method`, `parameter`, `payload`.
