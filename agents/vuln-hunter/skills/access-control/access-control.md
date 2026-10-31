# Skill: Broken Access Control (unauthenticated privileged access)

Operational playbook. Confirm whether privileged functionality (admin panels, management
endpoints, actions disclosed by robots.txt/sitemap) is reachable **without
authentication**. Non-destructive: only GET the page to prove it loads; never trigger the
privileged action (delete, promote, reset) to confirm.

## Trigger conditions
IF a hypothesis has class `ACCESS-CONTROL`
AND the endpoint looks privileged — an admin-like path, or one disclosed only by
`robots.txt` / `sitemap.xml` (linked from no page).

## Required inputs
- `endpoint`, `method`.

## Procedure
THEN request the endpoint with a **fresh session that holds no cookies** (anonymous).
→ `anonymous.request/response.http`.
THEN inspect the response:
  - status code (200 vs 401/403 vs a redirect);
  - does the body contain the functionality (forms, action links), or a login form?

## Decision rules
- 200 with the privileged content, no login wall → access control is missing.
- 401 / 403, or the body is a login page (password field, `action="/login"`) → the
  endpoint is protected.

## Confirmation criteria (ALL must hold)
- The request carried no session/authentication.
- The response status is 200 with a non-empty body.
- The body is the functionality itself, not a login/redirect page.

## False-positive criteria (ANY)
- Status 401 or 403.
- The response is (or redirects to) a login page.

## Evidence requirements
- `anonymous.request.http` / `anonymous.response.http` (no Cookie header on the request).
- Note the status and that the body is the privileged page, not a login form.

## Safety
- Confirm with a read (GET of the panel) only. Do NOT invoke destructive actions it
  exposes (e.g. `/delete`) to "prove" it — reaching the panel unauthenticated is enough.

## Output
- Finding JSON (`contracts/finding.schema.md`) with:
  `class: "ACCESS-CONTROL"`, `status: confirmed|unconfirmed|false-positive`,
  `endpoint`, `method`, the `payload` (the anonymous request), and `evidence` file refs.
