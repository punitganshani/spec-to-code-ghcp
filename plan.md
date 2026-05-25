# Policy-filtering middleware plan

## Problem
Build a thin async Python 3.11 middleware layer that intercepts third-party API responses before they reach the application layer, applies externally configured policy checks for PII, profanity, and off-topic categories, and preserves existing client behavior except where policy requires sanitization or blocking. Added overhead must stay within 50ms.

## Current state
- Workspace inspection found no existing repository files, Python modules, or `requirements.txt` under `/Users/puneetghanshani/Github/test`.
- This plan therefore treats the work as greenfield and uses a spec-driven approach that can be executed once the actual async `httpx` client code is present.

## Epic
**Policy-governed response filtering middleware**

Build a thin, async, config-driven middleware layer that sits between the third-party provider client and the application layer, filters deserialized responses for PII, profanity, and off-topic content, and returns a stable, testable contract with pass, sanitize, or block outcomes while adding no more than 50ms of overhead.

Epic-level acceptance criteria:
- The middleware wraps an existing async `httpx` client instead of replacing it.
- Policy rules are externalized and reloadable.
- Clean payloads pass through unchanged.
- Violating payloads are either sanitized or blocked according to configured severity.
- The returned contract is deterministic and testable.
- Representative workloads remain within the latency budget.

## Features

### Feature 1: Response interception layer
Add a single integration seam that intercepts provider responses after deserialization and before application use.

### Feature 2: External policy configuration
Load filtering rules from external config, including rule type, severity, action, scope, and versioning.

### Feature 3: Policy evaluation engine
Traverse nested JSON-compatible payloads and apply configurable checks for PII, profanity, and off-topic categories.

Policy-specific coverage within this feature:
- **PII**: detect sensitive identifiers in configured fields or matched values and prefer targeted redaction or masking.
- **Profanity**: detect banned or severity-scored abusive terms in free-text fields and sanitize the offending text span or field.
- **Off-topic categories**: classify provider content against allowed/disallowed topic categories and flag, sanitize, or block at the field or item level.

### Feature 4: Decision and sanitization contract
Return a stable result object that preserves payload shape where possible and exposes structured violation metadata.

### Feature 5: Async client integration
Wrap the existing async `httpx` flow without adding framework dependencies or rewriting the client.

### Feature 6: Performance and observability safeguards
Ensure the layer is measurable, deterministic, concurrency-safe, and within the latency budget.

## User stories and acceptance criteria

### Feature 1: Response interception layer

#### Story 1.1: Intercept parsed provider responses
As an application integrator, I want filtering to occur after deserialization so policy logic can work with Python objects instead of raw transport bytes.

Acceptance criteria:
- The filtering seam receives Python data structures, not raw `httpx.Response` bytes, for standard flows.
- Response status and headers remain accessible if the client contract needs them.
- The middleware can be inserted at one explicit point in the existing async client flow.
- The design does not require rewriting existing request/transport logic.

#### Story 1.2: Preserve caller expectations
As an application caller, I want the middleware to preserve normal client behavior when no policy action is required.

Acceptance criteria:
- Given a clean payload, the result is `action="pass"`.
- The payload content and structure are unchanged.
- The caller does not need special-case logic for clean responses beyond the documented contract.

### Feature 2: External policy configuration

#### Story 2.1: Change rules without code edits
As a policy operator, I want to update rules through config so policy changes do not require code rewrites.

Acceptance criteria:
- Rules are defined outside the middleware code.
- Config supports at least rule ID, policy type, severity, action, matching scope, and optional metadata.
- Config changes can be loaded without process restart.
- The active config version is available to evaluation or decision metadata.

#### Story 2.2: Fail safely on invalid config
As a policy operator, I want invalid configuration to fail explicitly so unsafe defaults are not silently applied.

Acceptance criteria:
- Invalid config is surfaced as an explicit failure.
- The system does not silently skip malformed rules.
- Config validation happens before rules are used for live evaluation.

### Feature 3: Policy evaluation engine

#### Story 3.1: Detect violations in nested structures
As a policy owner, I want nested arrays and objects evaluated so violations cannot bypass filters just by changing shape.

Acceptance criteria:
- The evaluator traverses nested dict/list structures.
- Violations in deeply nested fields are reported with exact payload paths.
- Unknown fields are still evaluated when they contain JSON-compatible content.

#### Story 3.2: Support targeted sanitization
As an application caller, I want the middleware to sanitize only violating fields so usable content is preserved.

Acceptance criteria:
- Medium-severity matches return `action="sanitize"` and `flagged=True`.
- Only violating fields are redacted or transformed.
- Unrelated fields remain unchanged.
- Sanitization is deterministic and idempotent for the same config version.

#### Story 3.3: Support hard blocking
As a policy owner, I want severe violations blocked so unsafe content never reaches the application layer.

Acceptance criteria:
- High-severity matches return a blocked outcome or configured exception path.
- Blocking behavior is deterministic for the same payload and config version.
- Structured metadata records the blocking rule and affected path(s).

#### Story 3.4: Handle PII with targeted redaction
As a privacy owner, I want PII detected and redacted in a field-aware way so sensitive data is removed without discarding safe content.

Acceptance criteria:
- The spec defines which PII classes are in scope, such as email addresses, phone numbers, government identifiers, payment-like numbers, names, and provider-specific sensitive fields.
- PII rules support both field-targeted matching and value-pattern matching.
- Default behavior for non-severe PII matches is field-level masking or redaction, not whole-payload rejection.
- High-severity PII rules can escalate to block when policy requires it.
- Violation metadata identifies the PII class that triggered the action.

#### Story 3.5: Handle profanity in text-bearing fields
As a policy owner, I want profanity filtered in free-text fields so abusive content does not flow into the application unchanged.

Acceptance criteria:
- Profanity evaluation is limited to configured text-bearing fields or traversed string values.
- The spec distinguishes literal banned terms, normalized term matching, and severity-scored phrase rules.
- Default behavior is sanitizing the offending field or span and marking the result as flagged.
- Context-free false positives are accounted for through allowlists, scoped rules, or field exclusions defined in config.
- Violation metadata records the profanity rule ID and matched severity.

#### Story 3.6: Handle off-topic categories using policy taxonomy
As a policy owner, I want provider content checked against an allow/deny taxonomy so irrelevant categories can be filtered before reaching the application layer.

Acceptance criteria:
- The spec defines whether off-topic detection uses provider-supplied categories, mapped taxonomy values, keyword heuristics, or a combination.
- The config supports allowlisted categories, denylisted categories, and category-mapping rules.
- Off-topic handling can be configured per endpoint or provider context.
- Default behavior is to flag or remove offending category-bearing items while preserving unrelated content where possible.
- High-confidence denylisted categories can escalate to blocked outcomes if policy requires it.

### Feature 4: Decision and sanitization contract

#### Story 4.1: Expose a minimal testable interface
As a developer, I want a narrow async evaluation interface so the behavior is easy to unit test.

Acceptance criteria:
- The core evaluator exposes one async entry point over Python data structures.
- The returned decision includes `action`, `payload`, `violations`, and `flagged`.
- The decision payload remains JSON-serializable.
- The evaluator can be tested without live HTTP calls.

#### Story 4.2: Preserve downstream compatibility
As an application integrator, I want payload shape preservation so sanitization does not break downstream parsing.

Acceptance criteria:
- Sanitization does not remove unrelated keys or change top-level container types.
- Payload structure remains stable unless a rule explicitly requires blocking.
- Violation metadata is separate from the sanitized payload unless the caller contract requires embedding.

### Feature 5: Async client integration

#### Story 5.1: Keep the middleware thin
As a maintainer, I want a wrapper-based integration so the existing client remains the source of truth for transport behavior.

Acceptance criteria:
- The solution is implemented as a wrapper, decorator, or equivalent thin middleware seam.
- No new framework dependencies are introduced beyond `requirements.txt`.
- Request sending, retries, auth, and transport concerns remain outside the policy evaluator.

#### Story 5.2: Keep async behavior intact
As a platform engineer, I want the middleware to preserve async behavior so concurrency characteristics stay predictable.

Acceptance criteria:
- The evaluator is async-compatible with `await`-based call paths.
- The middleware does not introduce blocking I/O per request for config parsing or rule compilation.
- The integration supports concurrent requests without shared-state corruption.

### Feature 6: Performance and observability safeguards

#### Story 6.1: Meet the latency budget
As a platform engineer, I want filtering overhead capped so policy enforcement does not become a bottleneck.

Acceptance criteria:
- Representative benchmark coverage exists for clean, sanitize, and block paths.
- Added overhead is within 50ms for agreed representative payloads and rule counts.
- Rule compilation and config loading are cached across requests.

#### Story 6.2: Produce actionable diagnostics
As an operator, I want structured violation output so filtering decisions can be debugged safely.

Acceptance criteria:
- Each violation includes at least rule ID, severity, action, and payload path.
- Sanitized and blocked outcomes can be traced to the rules that caused them.
- Diagnostic output excludes unsafe raw content unless explicitly required by policy.

## Core contract

### Scope
- Intercept successful third-party responses after deserialization and before application use.
- Evaluate nested JSON-compatible Python structures.
- Apply externally configured rules for PII, profanity, and off-topic categories.
- Return either the original payload, a sanitized payload with metadata, or a blocked result.

### Policy-specific handling strategy

#### PII
- **Detection inputs**: configured field names, field paths, regex/pattern rules, provider-specific labels, and optional field classifiers.
- **Likely in-scope entities**: email, phone, address-like strings, account identifiers, government identifiers, payment-like numbers, names, and any provider-defined sensitive fields.
- **Default action**: targeted masking or redaction of the offending value or subfield.
- **Escalation path**: block only for configured high-severity PII classes or repeated/high-confidence matches.
- **Spec requirement**: define exactly which PII classes are supported in v1 and which are explicitly out of scope.

#### Profanity
- **Detection inputs**: configured banned-term lists, normalized string matching, regex rules, phrase severity, and field scoping.
- **Likely evaluation scope**: only text-bearing fields or string values, not numeric or structural fields.
- **Default action**: sanitize the offending field or text span and mark the payload as flagged.
- **Escalation path**: block only for configured severe or repeated abusive content.
- **Spec requirement**: define normalization rules, allowlist behavior, and false-positive handling.

#### Off-topic categories
- **Detection inputs**: provider-supplied category fields, mapped internal taxonomy, configured allowlists/denylists, endpoint-specific topic rules, and optional keyword heuristics when category labels are absent.
- **Likely evaluation scope**: item-level category fields, tags, labels, or content-type metadata before falling back to text heuristics.
- **Default action**: flag or remove only the offending item/field rather than discarding the entire payload.
- **Escalation path**: block only when the entire response is dominated by denylisted categories or policy explicitly requires it.
- **Spec requirement**: define the taxonomy source of truth and precedence order between provider categories, internal mappings, and heuristics.

### External rule/config requirements
- Config must support a `policy_type` of at least `pii`, `profanity`, or `off_topic`.
- Config must support rule-scoping by provider, endpoint, field path, category source, severity, and action.
- Config must support allowlists, denylists, exclusions, and optional category mappings.
- Config must support policy-specific metadata, such as PII class, profanity normalization mode, or category taxonomy version.

### Non-goals
- Rewriting the existing async `httpx` client.
- Introducing new framework dependencies beyond `requirements.txt`.
- Defaulting to raw-byte filtering in normal flows.

### Recommended default decisions
- **Evaluation level**: deserialized JSON / Python-object level.
- **Default partial-match behavior**: sanitize targeted fields and set `flagged=True`.
- **Default hard-fail behavior**: raise or return an explicit blocked outcome only for configured high-severity rules or invalid config.

### Minimal interface
```python
from dataclasses import dataclass
from typing import Any, Protocol

@dataclass(frozen=True)
class FilterDecision:
    action: str  # "pass", "sanitize", "block"
    payload: Any
    violations: list[dict[str, Any]]
    flagged: bool

class PolicyFilter(Protocol):
    async def evaluate(
        self,
        payload: Any,
        *,
        provider: str,
        endpoint: str,
        config_version: str | None = None,
    ) -> FilterDecision: ...
```

Contract invariants:
- Evaluation is pure over Python data structures.
- The returned payload remains JSON-serializable.
- Violations include rule ID, path, severity, and action.
- Sanitization is deterministic and idempotent for the same config version.

## Likely failure modes to make explicit in the spec
- **Schema drift**: provider field names or nesting change and rules stop matching correctly.
- **Over-filtering**: rules sanitize content that downstream logic depends on.
- **Under-filtering**: nested blobs, unknown keys, or encoded content bypass checks.
- **Type instability**: sanitization changes payload shape and breaks consumers.
- **Latency regression**: per-request config parsing or deep traversal exceeds budget.
- **Concurrency hazards**: shared config/rule state becomes inconsistent under async load.
- **Decision ambiguity**: callers cannot reliably distinguish pass, sanitize, and block.
- **Observability gaps**: decisions cannot be traced to specific rules and paths.

## Assumptions to validate early
- Payloads are small enough for in-memory traversal.
- Rule evaluation can stay in-process and still meet the latency budget.
- Config is cached rather than reparsed on every request.
- The caller contract can absorb structured decision metadata.
- Relevant violations exist in traversable JSON-compatible structures.

## Strict todo list
1. Write the epic summary, features, and feature boundaries in the implementation spec.
2. Define the exact integration seam in the existing async `httpx` client flow.
3. Specify the public decision contract and payload-shape invariants.
4. Specify the external config schema, severity model, reload semantics, and policy-specific metadata fields.
5. Define the v1 handling strategy for PII, including in-scope PII classes, field targeting, masking behavior, and block escalation rules.
6. Define the v1 handling strategy for profanity, including normalized matching, allowlists, field scoping, sanitization behavior, and severity rules.
7. Define the v1 handling strategy for off-topic categories, including taxonomy source, provider-to-internal mapping, allow/deny lists, and item-level versus payload-level actions.
8. Write user stories and acceptance criteria for every feature and policy type.
9. Create representative acceptance examples for clean, PII, profanity, off-topic, mixed-violation, malformed, and schema-drift cases.
10. Create unit test scenarios directly from the stories and acceptance examples.
11. Create latency and concurrency benchmark scenarios with pass/fail thresholds.
12. Implement config loading, validation, and cached compiled-rule preparation.
13. Implement nested payload traversal and path-aware rule evaluation.
14. Implement field-level sanitization behavior and blocked-outcome behavior.
15. Implement the async middleware/wrapper integration at the chosen seam.
16. Add structured violation metadata and any required safe diagnostics.
17. Run the unit, contract, and performance suite against representative samples.
18. Validate that the final behavior matches the written spec before rollout.

## Unit test scenarios

### Decision-path tests
- Clean payload returns `action="pass"` with unchanged payload.
- Payload with one sanitizable field returns `action="sanitize"` and `flagged=True`.
- Payload with multiple sanitizable fields sanitizes each violating path and preserves siblings.
- Payload with a high-severity rule match returns blocked behavior.
- Payload with no text-bearing fields returns pass-through behavior.
- Payload with mixed PII and profanity violations returns deterministic actions in configured precedence order.

### Traversal tests
- Violations inside nested dicts are detected.
- Violations inside nested lists are detected.
- Mixed dict/list nesting preserves accurate path reporting.
- Unknown fields are still traversed.
- `None`, booleans, numbers, and empty containers are handled safely.

### Sanitization tests
- Sanitization preserves top-level container type.
- Sanitization preserves non-violating siblings and ordering where relevant.
- Re-running evaluation with the same config produces the same sanitized payload.
- Already sanitized payloads are not mutated again unexpectedly.

### PII-specific tests
- Email-like values in configured fields are redacted.
- Phone-like values in configured fields are redacted.
- Provider-specific sensitive field names trigger redaction even when values do not match generic patterns.
- Non-sensitive lookalike strings do not trigger false positives when excluded by config.
- High-severity PII classes trigger blocked behavior when configured to do so.

### Profanity-specific tests
- Literal banned terms in text-bearing fields are sanitized.
- Normalized matching catches case and punctuation variants.
- Allowlisted words or phrases avoid false-positive sanitization.
- Profanity in non-text fields is ignored unless explicitly configured.
- Severe abusive phrases trigger blocked behavior when configured to do so.

### Off-topic-category tests
- Denylisted provider categories are flagged or removed at the configured scope.
- Allowed categories pass through unchanged.
- Provider category mappings to internal taxonomy produce the expected policy outcome.
- Endpoint-specific category rules override generic defaults where configured.
- Responses with mixed allowed and off-topic items preserve allowed items when item-level filtering is configured.

### Config tests
- Valid config loads and exposes a usable version identifier.
- Invalid config raises explicit validation failure.
- Missing required rule fields fail validation.
- Rule reload updates active behavior without restart.
- Cached config avoids reparsing when unchanged.
- Policy-type-specific config validation catches invalid PII classes, invalid profanity modes, or unknown category mappings.

### Contract tests
- `FilterDecision` always includes required fields.
- Violation entries include rule ID, path, severity, and action.
- Payload remains JSON-serializable after pass and sanitize outcomes.
- Wrapper integration preserves caller-visible behavior for clean responses.

### Async and concurrency tests
- Concurrent evaluations do not corrupt shared state.
- Concurrent config reads do not create inconsistent rule versions.
- Async evaluation does not perform blocking file reads in the hot path.

### Performance tests
- Clean path overhead stays within budget for representative payload sizes.
- Sanitization path overhead stays within budget for representative payload sizes.
- Block path overhead stays within budget for representative payload sizes.
- Rule-count growth is measured to detect non-linear regressions.

## Policy-specific acceptance examples to include in the spec
- A clean provider payload with nested objects and arrays that passes unchanged.
- A payload containing an email address in a customer-contact field that is masked while surrounding content remains intact.
- A payload containing profanity in a free-text summary that is sanitized and flagged.
- A payload whose item category maps to a denylisted internal taxonomy value and is removed or flagged at item scope.
- A payload containing both PII and profanity in different fields to validate action precedence and multi-violation metadata.
- A payload with provider schema drift, such as renamed category fields, to define safe fallback behavior.

## Notes
- Because the repository is empty, this plan focuses on the specification package and execution sequence rather than file-by-file code changes.
- Implementation should not begin until the epic, features, user stories, acceptance criteria, strict todo list, and unit test scenarios are written down and agreed.
