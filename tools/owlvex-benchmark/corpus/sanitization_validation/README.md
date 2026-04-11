# GR-003 Sanitization and Validation Corpus

This corpus validates Guardrail Rule `GR-003`:

`Trust state may only transition through explicit, registered sanitizers or validators.`

v1 assumption:

- all registered sanitizers are trusted and complete
- unregistered transformations do not change trust state
- wrong-context sanitizers do not change trust state
