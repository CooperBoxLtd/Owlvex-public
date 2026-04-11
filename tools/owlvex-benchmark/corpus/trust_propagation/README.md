# GR-002 Trust Propagation Corpus

This corpus validates Guardrail Rule `GR-002`:

`A variable's trust state must be preserved, transformed, or overwritten deterministically across assignments and branches.`

The cases in this folder focus on:

- unsafe propagation
- safe propagation
- branch merging
- reassignment overwrite behavior
- sanitization-driven state transitions

At execution sinks, `MIXED` must be treated as unsafe.
