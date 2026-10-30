# Skill: Path Traversal (Directory Traversal)

Operational playbook. Confirm whether a parameter used to reference a file lets you escape
the intended directory and read arbitrary files. Non-destructive: **read** a well-known
file as proof; never write or delete.

## Trigger conditions
IF a hypothesis has class `PATH-TRAVERSAL`
AND a parameter plausibly names a file/path (file, filename, path, doc, document, page,
   template, download, view, attachment, resource, folder).

## Required inputs
- `endpoint`, `method`, the `parameter` carrying the file reference.
- A plausible benign value (e.g. a filename the app would normally serve) for a control.

## Procedure
THEN send a benign request (a normal filename) and record the response as a control.
→ save `control-benign.request.http` / `.response.http`.
THEN send traversal payloads aimed at a well-known file, trying a few variants:
  - `../../../../../../etc/passwd`
  - `....//....//....//....//etc/passwd` (defeats a single `../` strip)
  - encoded variants if the raw ones are filtered (`%2e%2e%2f`, `..%2f`)
  - Windows target `..\..\..\windows\win.ini` if the stack looks like Windows
→ save `traversal.request.http` / `.response.http`.
THEN inspect the response for proof of a file OUTSIDE the intended directory.

## Decision rules
- The response contains the signature of a known system file that the endpoint should not
  serve → candidate confirmation. For `/etc/passwd` the signature is a line matching
  `root:.*:0:0:`.
- The same signature must be ABSENT from the benign control (so it is the traversal, not
  normal content, that produced it).

## Confirmation criteria (ALL must hold)
- A traversal payload returns content matching a known outside-file signature
  (e.g. `root:.*:0:0:` for `/etc/passwd`), reproducibly.
- That signature is absent from the benign control response.
- Evidence captured: benign control AND the traversal request/response.

## False-positive criteria (ANY)
- Traversal requests return 400/403/404, a redirect to login, or an empty/error body
  (path rejected or sanitized).
- The signature also appears in the benign control (it is normal page content, not a leak).
- The app normalizes/strips `..` so the resolved path stays inside the intended directory.

## Evidence requirements
- `control-benign.request.http`, `control-benign.response.http`.
- `traversal.request.http`, `traversal.response.http`.
- Note the exact payload that worked and the signature line observed.

## Output
- Finding JSON (`contracts/finding.schema.md`) with:
  `class: "PATH-TRAVERSAL"`, `status: confirmed|unconfirmed|false-positive`,
  `endpoint`, `method`, `parameter`, the confirming `payload`, and `evidence` file refs.
