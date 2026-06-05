## 2024-05-17 - Avoid redundant terminal operations in Kotlin
**Learning:** Chained terminal operations like `groupBy`, `mapValues`, `count`, and `sumOf` in Kotlin create O(N*M) iterations and allocate unnecessary intermediate collections (e.g., intermediate Maps for `groupBy`), which can slow down large data aggregations like generating report statistics.
**Action:** Replace multiple chained terminal operations with a single-pass `forEach` or `fold` to aggregate metrics in one loop, preventing intermediate object allocations and optimizing performance.
