## 2024-05-20 - Optimize Collection Iterations
**Learning:** Found multiple chained collection operations (`sumOf`, `average`, `minByOrNull`, `maxByOrNull`) within flow emission blocks. These cause redundant O(N) traversals and intermediate allocations.
**Action:** Replaced the multi-pass terminal operations with a single-pass `forEach` loop or standard `for` loop to compute all aggregations concurrently, improving performance.
