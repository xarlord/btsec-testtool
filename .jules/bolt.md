## 2026-06-15 - Optimize Collection Operations
**Learning:** For statistical aggregations over Kotlin collections, prioritize single-pass iterations (e.g., using `forEach` or `fold`) over multiple redundant terminal operations like `sumOf`, `average`, `filter`, or `maxByOrNull`. This is essential to optimize performance and prevent intermediate object allocations.
**Action:** Always replace multiple terminal collection operations with single-pass loops when performing aggregations or calculating statistics over lists.
