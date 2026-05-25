# Skill: PII Filtering

- Detect sensitive values from configured field paths and value patterns.
- Prefer targeted masking/redaction for non-severe matches.
- Escalate to block for configured high-severity PII classes.
- Emit structured violation metadata (`rule_id`, `path`, `severity`, `policy_type`).
