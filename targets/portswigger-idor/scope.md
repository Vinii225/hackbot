# Scope — portswigger-idor

> Authorized use only. Fill in YOUR lab instance URL, then run.
> PortSwigger lab: "Insecure direct object references" (or any access-control lab).

## Authorization
- [ ] I confirm this is my own PortSwigger Web Security Academy lab instance.

## In scope
```
# Paste your lab URL (host only). Example shape:
https://REPLACE-ME.web-security-academy.net
```

## Out of scope
```
# Everything else, including PortSwigger infra and the exploit-server host.
```

## Credentials
```
user: wiener / peter          # standard low-priv lab account
victim object: carlos         # or the numeric id the lab exposes
```

## Hints
- Objective: IDOR / broken access control.
- Note the endpoint that serves an object by a client-controlled id (path or query).
