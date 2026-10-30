# Contract: Recon → Coordinator

```json
{
  "from": "recon",
  "target": "target-example",
  "status": "ok | partial | blocked",
  "artifacts": {
    "tech": "targets/target-example/recon/tech.json",
    "surface": "targets/target-example/recon/surface.json",
    "js": "targets/target-example/recon/js.json",
    "hypotheses": "targets/target-example/recon/hypotheses.json"
  },
  "counts": {
    "endpoints": 12,
    "parameters": 20,
    "js_files": 3,
    "hypotheses": { "IDOR": 2, "CMDI": 1, "other": 1 }
  },
  "requests_used": 37,
  "notes": "Authenticated recon done as wiener. One endpoint rate-limited.",
  "blocked_reason": null
}
```

| Field | Required | Notes |
|-------|----------|-------|
| `status` | yes | `blocked` requires `blocked_reason`. |
| `artifacts` | yes | Paths that must exist on disk. |
| `counts` | yes | Quick summary for prioritization. |
| `requests_used` | yes | Added to the engagement counter. |
| `blocked_reason` | if blocked | e.g. "scope unreachable", "needs credentials". |

The Coordinator validates that every `artifacts` path exists and that
`hypotheses.json` conforms to `hypothesis.schema.md`.
