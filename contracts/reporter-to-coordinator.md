# Contract: Reporter → Coordinator

```json
{
  "from": "reporter",
  "target": "target-example",
  "report_file": "targets/target-example/reports/REPORT.md",
  "included": {
    "critical": 0,
    "high": 1,
    "medium": 1,
    "low": 0
  },
  "dropped": [
    { "finding": "F-003", "reason": "status not confirmed" },
    { "finding": "F-004", "reason": "evidence files missing" }
  ]
}
```

| Field | Required | Notes |
|-------|----------|-------|
| `report_file` | yes | Must exist on disk. |
| `included` | yes | Count of confirmed findings by severity in the report. |
| `dropped` | yes | Findings not included and why (never silently omit). |

This closes the loop; the Coordinator marks the engagement `complete`.
