# Skill: Latency Guardrails

- Keep middleware overhead under 50ms on representative payloads.
- Avoid per-request config parsing and regex recompilation.
- Use cached config + compiled rules with mtime-based reload checks.
- Benchmark clean/sanitize/block paths under concurrency.
