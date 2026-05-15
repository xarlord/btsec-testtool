## 2024-05-15 - Single-pass Iteration for Statistics Aggregation
**Learning:** Using multiple terminal operations (like `sumOf`, `minByOrNull`, `maxByOrNull`, `average`) on collections causes redundant O(N) traversals and intermediate allocations, which can be a performance bottleneck when dealing with larger datasets like test results.
**Action:** Prioritize single-pass iterations (e.g., using `forEach` or `fold`) over multiple terminal operations to optimize performance and prevent unnecessary allocations.
