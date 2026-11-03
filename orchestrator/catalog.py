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
}

_ALIASES = {"SQL-INJECTION": "SQLI", "PATH_TRAVERSAL": "PATH-TRAVERSAL",
            "ACCESS_CONTROL": "ACCESS-CONTROL"}


def meta_for(cls):
    return CLASS_META.get(_ALIASES.get(cls, cls))
