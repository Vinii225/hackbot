# Scope — target-example

> **Human-authored.** The agents read this file and must NOT act outside it.
> If this file is empty, incomplete, or ambiguous, the Coordinator STOPS and asks you.

## Authorization

- [ ] I confirm I am authorized to test the target(s) listed below.
- Authorization source: _(e.g. "PortSwigger Web Security Academy — my own lab instance")_

## In scope

List exact hosts/paths. Only these may be touched. Subdomains and external links are
**not** in scope unless listed here explicitly.

```
# host only — replace with your lab instance
https://YOUR-LAB-ID.web-security-academy.net
```

## Out of scope

```
# anything not listed in "In scope"
# PortSwigger infrastructure, email/exploit-server hosts unless the lab requires them
```

## Credentials (optional, for authenticated testing)

```
user:    wiener / peter
victim:  carlos         # object owner to attempt IDOR against (object hint only)
```

## Notes / target hints

- Objective focus for MVP: IDOR / Broken Access Control, Command Injection.
- Any lab-specific hints (known endpoint, parameter, intended victim) go here.
