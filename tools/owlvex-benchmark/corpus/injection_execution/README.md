# GR-001 Injection and Execution Corpus

This corpus validates Guardrail Rule `GR-001`:

`Unsafe or mixed trust reaching an execution sink must be reported as an execution-risk finding.`

The rule is intentionally thin and depends on GR-002 trust evaluation.

This means:

- GR-001 must not recompute trust
- GR-001 must only consume trust state and sink information
- `MIXED` must behave as unsafe at execution sinks
