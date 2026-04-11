# GR-005 Context Mismatch Corpus

These fixtures validate a narrow GR-005 rule:

- a transformation only remains safe when it is valid for the target sink context
- `generic` sanitizers are accepted in any sink context for v1
- context mismatch overrides `SAFE`

This pack consumes:

- GR-002 trust state and transformation metadata
- GR-004 sink context

It does not recompute trust or sink shape on its own.
