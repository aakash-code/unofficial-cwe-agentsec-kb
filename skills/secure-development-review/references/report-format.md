# Report format

Open with one line on scope: what was reviewed, how (manual trace, scanner,
tests run), and anything excluded.

Then list findings, most severe first:

```text
[Severity] Title — confidence: High|Medium|Low — status: Confirmed|Probable|Needs Review
CWE: CWE-<id> <name> (mapping_usage: Allowed)   |   Rule: ASKB-…  (if one applies)
     ↑ name and usage copied from the KB lookup; write "(unverified)" if you couldn't look it up
Evidence: path/to/file.py:42-47 — short, redacted snippet or data-flow summary
Root cause: the missing or incorrect control
Preconditions: what an attacker must control or reach
Impact: what happens in this application
Why this CWE: one or two sentences grounded in the entry's description
Fix: concrete code change
Verify: the regression test or check that proves the fix
```

Severity is Critical / High / Medium / Low / Informational, judged on this
app's exposure and data, not on the CWE.

Close with:
- **Not reviewed**: directories, languages, runtime behavior, dependencies' CVEs.
- **Limitations**: static review only, heuristic scanner coverage, assumptions made.
- No statement that the code is secure.

If there are no confirmed findings, say what was checked and why it holds up.
"No issues found" alone isn't useful.

## Machine-readable output

When the user wants JSON (CI, ticket import), emit objects matching
`schemas/finding.schema.json` in the plugin root (`${CLAUDE_PLUGIN_ROOT}`). Its
fields are `rule_id`, `cwe_ids`, `title`, `severity`, `confidence`, `evidence{path,line,snippet}`,
`impact`, `safe_verification[]`, `remediation[]`, and `disposition`. Lowercase
the severity and confidence values.
