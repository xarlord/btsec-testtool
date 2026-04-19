## 2024-04-19 - Statistical Aggregations Anti-Pattern
**Learning:** The codebase relies on multiple chained terminal operations (`sumOf`, `filter`, `maxByOrNull`, `average`) over the same collections for dashboard statistics, leading to redundant O(N) iterations and unnecessary intermediate object allocations (e.g., from `filter` and `map`).
**Action:** Always prioritize single-pass iterations (like `forEach` or `fold`) over multiple terminal operations when calculating multiple aggregate metrics from a single list.
