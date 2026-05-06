## 2024-05-06 - Single-Pass Iteration for Statistics Aggregation
**Learning:** Calling `.sumOf()`, `.average()`, `.minByOrNull()`, and `.maxByOrNull()` consecutively on collections like `fuzzingResults` causes multiple iterations over the same data list. This incurs $O(k \cdot n)$ complexity and creates unnecessary intermediate lambda and sequence allocations.
**Action:** Always combine statistical aggregations into a single-pass `forEach` loop to calculate multiple variables simultaneously when dealing with larger datasets like lists of reports or tests.
