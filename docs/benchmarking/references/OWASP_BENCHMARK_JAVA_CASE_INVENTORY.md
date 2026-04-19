# OWASP Benchmark Java Case Inventory

This inventory turns the first OWASP Benchmark Java slice into concrete Owlvex benchmark assets.

It answers:

- which Java families are in the first external slice now
- which exact Owlvex rule codes back them
- which demo fixtures currently stand in as the local benchmark inventory
- which Java families exist in Owlvex but are intentionally outside the first slice

Machine-readable source:

- [owasp-benchmark-java-slice.manifest.json](D:/Dev/repos/CodeScanner/docs/benchmarking/references/owasp-benchmark-java-slice.manifest.json)

## Included In The First OWASP Java Slice

| OWASP area | Owlvex issue | Rule | Unsafe fixture | Safe fixture |
| --- | --- | --- | --- | --- |
| Command Injection | `owlvex.issue.command_injection.001` | `GR-001` | [46-java-command-injection-unsafe.java](D:/Dev/repos/CodeScanner/tools/demo/46-java-command-injection-unsafe.java:1) | [47-java-command-injection-safe.java](D:/Dev/repos/CodeScanner/tools/demo/47-java-command-injection-safe.java:1) |
| SQL Injection | `owlvex.issue.sql_injection.001` | `SQ-001` | [48-java-sqli-unsafe.java](D:/Dev/repos/CodeScanner/tools/demo/48-java-sqli-unsafe.java:1) | [49-java-sqli-safe.java](D:/Dev/repos/CodeScanner/tools/demo/49-java-sqli-safe.java:1) |
| Path Traversal | `owlvex.issue.path_traversal.001` | `PT-001` | [50-java-path-traversal-unsafe.java](D:/Dev/repos/CodeScanner/tools/demo/50-java-path-traversal-unsafe.java:1) | [51-java-path-traversal-safe.java](D:/Dev/repos/CodeScanner/tools/demo/51-java-path-traversal-safe.java:1) |

## Adjacent Java Families In Owlvex, But Outside The First OWASP Slice

These are real Java deterministic families in Owlvex, but they should not be part of the first public OWASP Java slice claim.

| Owlvex issue | Rule | Unsafe fixture | Safe fixture | Why kept out of first slice |
| --- | --- | --- | --- | --- |
| `owlvex.issue.ssrf.001` | `SR-001` | [52-java-ssrf-unsafe.java](D:/Dev/repos/CodeScanner/tools/demo/52-java-ssrf-unsafe.java:1) | [53-java-ssrf-safe.java](D:/Dev/repos/CodeScanner/tools/demo/53-java-ssrf-safe.java:1) | maps only partially to OWASP's broader trust-boundary area |
| `owlvex.issue.weak_jwt_validation.001` | `JW-001` | [54-java-jwt-validation-unsafe.java](D:/Dev/repos/CodeScanner/tools/demo/54-java-jwt-validation-unsafe.java:1) | [55-java-jwt-validation-safe.java](D:/Dev/repos/CodeScanner/tools/demo/55-java-jwt-validation-safe.java:1) | product-real but not a clean first OWASP Java external category match |
| `owlvex.issue.insecure_deserialization.001` | `DS-001` | [56-java-deserialization-unsafe.java](D:/Dev/repos/CodeScanner/tools/demo/56-java-deserialization-unsafe.java:1) | [57-java-deserialization-safe.java](D:/Dev/repos/CodeScanner/tools/demo/57-java-deserialization-safe.java:1) | product-real but should be discussed separately from the first narrow slice |

## Why This Inventory Matters

Without a concrete inventory, an external benchmark slice stays too abstract.

This inventory makes the slice auditable:

- the included scope is explicit
- the excluded scope is explicit
- each mapped family has an unsafe/safe pair
- the first external claim can be traced back to concrete local fixtures and rule codes
