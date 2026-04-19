# External Benchmark Plan

## Purpose

External benchmarks give Owlvex a credibility anchor.

They do not replace Owlvex-native product benchmarks.

## Recommended External Sources

### OWASP Benchmark

Role:

- primary external anchor for deterministic proof claims

### Juliet / SARD

Role:

- secondary CWE-oriented corpus

Initial use:

- selective CWE slices only
- start with command injection, SQL injection, and path traversal
- treat insecure deserialization as a later extension

### SecurityEval

Role:

- external reference for AI security reasoning and code-security behavior

### CyberSecEval / Purple Llama

Role:

- external reference for broader AI security evaluation

## Working Rule

Use external benchmarks as:

- credibility anchors
- comparison references
- import sources for carefully chosen slices

Do not use them as:

- a replacement for Owlvex-native evaluation
- a shortcut to claims the product has not earned

## Recommended Order

1. use Owlvex-native proof and AI benchmarks as the primary quality gates
2. use OWASP Benchmark Java as the first external proof anchor
3. use selective Juliet / SARD slices as a second external proof reference
4. use SecurityEval and CyberSecEval as AI calibration references, not primary product scorecards
