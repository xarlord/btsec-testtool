## 2024-05-24 - Single-pass aggregations
**Learning:** Multiple terminal operations (`count`, `sumOf`) on the same collection for different properties causes redundant traversals and unnecessary allocations, especially with nested collections.
**Action:** Collapse these into a single pass (e.g., `forEach`) to avoid O(N*M) redundant iterations.
