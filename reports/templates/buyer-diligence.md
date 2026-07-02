# AppGuardrail Buyer Diligence Report

This template is generated from normalized AppGuardrail findings through
`appguardrail_core.reports.render_buyer_diligence_report`.

Use it when a founder, agency, or acquiring team needs evidence that shows:

- what was scanned,
- which findings block launch or sale diligence,
- how findings map to OWASP/CWE/SAMM references,
- what remediation and verification steps remain,
- which raw secrets or logs were intentionally excluded from the report.

Required generated sections:

1. Executive Readout
2. Scope And Evidence Handling
3. Findings Summary
4. Detailed Findings
5. Buyer Follow-Up Checklist

The generated report must not include raw customer secrets, authorization
headers, JWT values, or full CI logs.
