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
}

_ALIASES = {"SQL-INJECTION": "SQLI", "PATH_TRAVERSAL": "PATH-TRAVERSAL",
            "ACCESS_CONTROL": "ACCESS-CONTROL", "OPEN_REDIRECT": "OPEN-REDIRECT",
            "HOST_HEADER": "HOST-HEADER"}


def meta_for(cls):
    return CLASS_META.get(_ALIASES.get(cls, cls))
