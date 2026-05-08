## 2024-05-24 - Single-Pass Iterations for Aggregations
**Learning:** Using multiple terminal collection operations (like `sumOf`, `maxByOrNull`, `minByOrNull`, and `map`) in Kotlin sequentially over the same collection causes redundant iterations and intermediate allocations, significantly impacting performance on large datasets.
**Action:** Prioritize single-pass iterations (e.g., using `forEach` or `fold`) to compute multiple aggregate values simultaneously, optimizing performance and reducing memory overhead.
