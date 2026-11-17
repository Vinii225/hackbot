# Skill: Username Enumeration

Operational playbook. Confirm whether the login (or reset) response differs for a valid
versus an invalid username, leaking which accounts exist. Non-destructive: two failed
logins with a wrong password; never brute-force passwords.

## Trigger conditions
IF a hypothesis has class `USER-ENUM` AND an endpoint authenticates users.

## Procedure
1. Submit a known-valid username with a wrong password.
2. Submit a random (invalid) username with a wrong password.

## Confirmation criteria
- The two responses differ (status or body) — a valid/invalid username oracle exists.

## False-positive criteria
- The responses are identical for valid and invalid usernames.

## Evidence requirements
- `valid-username.*` and `invalid-username.*`.

## Output
- Finding JSON with `class: "USER-ENUM"`, `status`, `endpoint`, `method`, and `evidence`.
