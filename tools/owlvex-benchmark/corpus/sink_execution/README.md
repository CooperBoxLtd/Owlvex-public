# GR-004 Sink Execution Corpus

This corpus validates Guardrail Rule `GR-004`:

`Execution-relevant sinks must be identified deterministically, including aliases and simple wrappers, without recomputing trust.`

v1 scope is intentionally narrow:

- `exec`
- `execSync`
- `spawn`
- `spawnSync`

The evaluator must answer:

- which sink was called
- what sink kind it represents
- which argument position is sink-relevant
- whether the sink is dangerous in this usage form
