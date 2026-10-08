# Security review output contract

Use this structure for each finding:

```json
{
  "rule_id": "ASKB-CATEGORY-000",
  "cwe_ids": ["CWE-000"],
  "title": "Short evidence-led title",
  "severity": "low | medium | high | critical",
  "confidence": "low | medium | high",
  "evidence": {"path": "relative/path", "line": 1, "snippet": "redacted source evidence"},
  "impact": "Why the condition could matter",
  "safe_verification": ["Local, non-destructive confirmation step"],
  "remediation": ["Concrete, testable fix"],
  "disposition": "needs-human-review"
}
```

Prefix the full response with scope and authorization assumptions. End it with
limitations, unreviewed areas, and a statement that review output is not a
guarantee of security.
