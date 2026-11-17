"""Central catalog: each vulnerability class mapped to its CWE, OWASP Top 10 category and
default severity, so reports stay consistent. New classes register their metadata here."""
from __future__ import annotations

CLASS_META = {
    "IDOR": {"title": "Insecure Direct Object Reference", "cwe": "CWE-639",
             "owasp": "A01:2021 Broken Access Control", "severity": "high"},
    "CMDI": {"title": "OS Command Injection", "cwe": "CWE-78",
             "owasp": "A03:2021 Injection", "severity": "high"},
    "PATH-TRAVERSAL": {"title": "Path Traversal", "cwe": "CWE-22",
                       "owasp": "A01:2021 Broken Access Control", "severity": "high"},
    "XSS": {"title": "Reflected Cross-Site Scripting", "cwe": "CWE-79",
            "owasp": "A03:2021 Injection", "severity": "medium"},
    "ACCESS-CONTROL": {"title": "Broken Access Control", "cwe": "CWE-284",
                       "owasp": "A01:2021 Broken Access Control", "severity": "high"},
    "SQLI": {"title": "SQL Injection", "cwe": "CWE-89",
             "owasp": "A03:2021 Injection", "severity": "high"},
    "SSTI": {"title": "Server-Side Template Injection", "cwe": "CWE-1336",
             "owasp": "A03:2021 Injection", "severity": "high"},
    "OPEN-REDIRECT": {"title": "Open Redirect", "cwe": "CWE-601",
                      "owasp": "A01:2021 Broken Access Control", "severity": "medium"},
    "SSRF": {"title": "Server-Side Request Forgery", "cwe": "CWE-918",
             "owasp": "A10:2021 Server-Side Request Forgery", "severity": "high"},
    "CORS": {"title": "CORS Misconfiguration", "cwe": "CWE-942",
             "owasp": "A05:2021 Security Misconfiguration", "severity": "medium"},
    "XXE": {"title": "XML External Entity Injection", "cwe": "CWE-611",
            "owasp": "A05:2021 Security Misconfiguration", "severity": "high"},
    "HOST-HEADER": {"title": "Host Header Injection", "cwe": "CWE-644",
                    "owasp": "A05:2021 Security Misconfiguration", "severity": "medium"},
    "CSRF": {"title": "Cross-Site Request Forgery", "cwe": "CWE-352",
             "owasp": "A01:2021 Broken Access Control", "severity": "medium"},
    "CLICKJACKING": {"title": "Clickjacking (missing frame protection)", "cwe": "CWE-1021",
                     "owasp": "A05:2021 Security Misconfiguration", "severity": "low"},
    "GRAPHQL": {"title": "GraphQL Introspection Exposed", "cwe": "CWE-200",
                "owasp": "A05:2021 Security Misconfiguration", "severity": "low"},
    "JWT": {"title": "JWT alg:none Signature Bypass", "cwe": "CWE-347",
            "owasp": "A07:2021 Identification and Authentication Failures", "severity": "high"},
    "INFO-DISCLOSURE": {"title": "Verbose Error / Information Disclosure", "cwe": "CWE-209",
                        "owasp": "A05:2021 Security Misconfiguration", "severity": "medium"},
    "DIR-LISTING": {"title": "Directory Listing Enabled", "cwe": "CWE-548",
                    "owasp": "A05:2021 Security Misconfiguration", "severity": "low"},
    "LDAPI": {"title": "LDAP Injection", "cwe": "CWE-90",
              "owasp": "A03:2021 Injection", "severity": "high"},
    "MASS-ASSIGNMENT": {"title": "Mass Assignment", "cwe": "CWE-915",
                        "owasp": "A01:2021 Broken Access Control", "severity": "high"},
    "USER-ENUM": {"title": "Username Enumeration", "cwe": "CWE-204",
                  "owasp": "A07:2021 Identification and Authentication Failures",
                  "severity": "medium"},
    "PROTO-POLLUTION": {"title": "Prototype Pollution", "cwe": "CWE-1321",
                        "owasp": "A08:2021 Software and Data Integrity Failures",
                        "severity": "high"},
}

# Concise, class-level remediation guidance surfaced in every report next to the finding.
REMEDIATION = {
    "IDOR": "Enforce per-object authorization on every request (check the session owns the "
            "object); do not rely on unguessable ids.",
    "CMDI": "Never build OS commands from user input. Call APIs directly, or pass arguments "
            "as an argv array with no shell; allowlist expected values.",
    "PATH-TRAVERSAL": "Resolve the final path and confirm it stays within the intended base "
                      "directory; reject '..' and absolute paths; prefer an id-to-path map.",
    "XSS": "Contextually output-encode all user data (HTML/attribute/JS) and set a strict "
           "Content-Security-Policy; prefer framework auto-escaping.",
    "ACCESS-CONTROL": "Require authentication and authorization on every privileged route by "
                      "default (deny-by-default); never rely on an unlinked/obscure URL.",
    "SQLI": "Use parameterized queries / prepared statements for all data access; never "
            "concatenate input into SQL; apply least-privilege DB accounts.",
    "SSTI": "Never render user input as a template. Pass it as template data/variables, use "
            "a logic-less or sandboxed engine, and allowlist any dynamic fields.",
    "OPEN-REDIRECT": "Do not redirect to user-supplied URLs. Use an allowlist of permitted "
                     "destinations or relative paths only; validate the host.",
    "SSRF": "Allowlist outbound hosts, resolve and block private/link-local ranges, disable "
            "unused URL schemes and redirects, and segment the metadata endpoint.",
    "CORS": "Reflect only an allowlisted set of trusted origins; never echo arbitrary "
            "Origins, and never combine a wildcard origin with credentials.",
    "XXE": "Disable external entities and DTD processing in the XML parser (set secure "
           "features / FEATURE_SECURE_PROCESSING); prefer JSON where possible.",
    "HOST-HEADER": "Build absolute URLs from a configured canonical host, not the request "
                   "Host header; validate Host against an allowlist.",
    "CSRF": "Require an unpredictable per-session anti-CSRF token on all state-changing "
            "requests and set SameSite cookies.",
    "CLICKJACKING": "Send 'X-Frame-Options: DENY' (or a CSP 'frame-ancestors' directive) on "
                    "sensitive HTML responses.",
    "GRAPHQL": "Disable introspection in production and enforce authorization and query "
               "depth/complexity limits on the GraphQL endpoint.",
    "JWT": "Reject 'alg:none' and pin the expected algorithm; verify the signature with a "
           "strong secret/key; validate iss/aud/exp.",
    "INFO-DISCLOSURE": "Return generic error pages; log details server-side only. Disable "
                       "debug mode and stack traces in production.",
    "DIR-LISTING": "Disable automatic directory indexing (e.g. Options -Indexes / autoindex "
                   "off) and serve an explicit index or 403 for directories.",
    "LDAPI": "Escape LDAP special characters per RFC 4515, or use parameterized LDAP APIs; "
             "validate and allowlist input used in filters.",
    "MASS-ASSIGNMENT": "Bind only an explicit allowlist of client-settable fields; never "
                       "auto-bind privileged fields (role, isAdmin) from the request body.",
    "USER-ENUM": "Return identical responses and timing for valid and invalid usernames on "
                 "login, signup and password reset.",
    "PROTO-POLLUTION": "Reject or strip __proto__/constructor/prototype keys before merging "
                       "untrusted JSON; use Map or null-prototype objects and safe-merge.",
}
for _cls, _fix in REMEDIATION.items():
    CLASS_META[_cls]["remediation"] = _fix

_ALIASES = {"SQL-INJECTION": "SQLI", "PATH_TRAVERSAL": "PATH-TRAVERSAL",
            "ACCESS_CONTROL": "ACCESS-CONTROL", "OPEN_REDIRECT": "OPEN-REDIRECT",
            "HOST_HEADER": "HOST-HEADER", "INFO_DISCLOSURE": "INFO-DISCLOSURE",
            "DIR_LISTING": "DIR-LISTING", "DIRECTORY-LISTING": "DIR-LISTING",
            "LDAP": "LDAPI", "LDAP-INJECTION": "LDAPI", "MASS_ASSIGNMENT": "MASS-ASSIGNMENT",
            "USER_ENUM": "USER-ENUM", "PROTOTYPE-POLLUTION": "PROTO-POLLUTION",
            "PROTO_POLLUTION": "PROTO-POLLUTION"}


def meta_for(cls):
    return CLASS_META.get(_ALIASES.get(cls, cls))
