# Agents

## policy-architect
- Owns policy taxonomy, severity model, and rule lifecycle.
- Approves PII/profanity/off-topic rule definitions before activation.

## middleware-engineer
- Owns async wrapper integration and contract stability.
- Ensures no transport/client rewrite and no blocking I/O in hot path.

## policy-qa
- Owns acceptance examples, unit scenarios, and conformance checks.
- Verifies pass/sanitize/block behavior and latency gates.
