# Skill: IDOR / Broken Access Control

Operational playbook. Confirm whether a client-controlled object identifier lets one
user access another user's object without authorization. Non-destructive: **read** an
unauthorized object as proof; never modify/delete someone else's data.

## Trigger conditions
IF a hypothesis has class `IDOR`
AND the endpoint contains a client-controlled object identifier
   (numeric id, UUID, username, filename, account/order/message id in path, query, body,
   header, or cookie).

## Required inputs
- `endpoint`, `method`, the `parameter` carrying the identifier.
- At least one identifier you are **authorized** to access (your own object).
- Ideally two test accounts, OR two objects owned by different users in the lab.
- Session/credentials for the acting user (from `scope.md` / message).

## Procedure
THEN establish the baseline: as user A, request your own object; record the id and the
authorized response. → save `request-a.http` / `response-a.http`.
THEN identify another object id that belongs to a different owner (user B, or the lab's
target id such as `carlos`). Do not brute-force broadly — use ids revealed by recon or
the lab description.
THEN replace the identifier with user B's id while keeping user A's session.
→ save `request-b.http` / `response-b.http`.
THEN compare response A vs response B.
THEN (access-control variant) if the endpoint is an admin/privileged action, repeat as a
low-privilege user and check whether the action still succeeds.

## Decision rules
- Access succeeds as a different/lower-privileged user → candidate confirmation.
- Distinguish from intended sharing: check whether the app *should* expose this object
  to user A (public resource, shared link). If intended → false positive.

## Confirmation criteria (ALL must hold)
- User A's session (or a lower-privileged session) received user B's / privileged data
  (status 200 + the other owner's data present), OR performed a privileged action.
- The data returned is clearly scoped to another principal (different name, email, order,
  balance, etc.), not generic/public content.
- Evidence captured: baseline request/response AND cross-object request/response.

## False-positive criteria (ANY)
- Cross-object request returns 401/403/404/redirect-to-login, or empty/placeholder.
- The resource is public by design, or A was explicitly granted access.
- The "other" id actually resolves to A's own object.

## Evidence requirements
- `request-a.http`, `response-a.http` (authorized baseline).
- `request-b.http`, `response-b.http` (unauthorized access attempt).
- Note the distinguishing field(s) that prove the data belongs to another owner.

## Output
- Finding JSON (`contracts/finding.schema.md`) with:
  `class: "IDOR"`, `status: confirmed|unconfirmed|false-positive`,
  `endpoint`, `method`, `parameter`, `evidence` file refs, and a one-line `proof`
  naming the field that proves cross-user access.
