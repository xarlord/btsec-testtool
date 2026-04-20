## 2024-05-23 - Avoid redundant terminal operations in aggregations
**Learning:** For statistical aggregations over collections in Kotlin, using multiple redundant terminal operations like `sumOf`, `average`, `filter`, or `maxByOrNull` incurs a performance penalty from multiple passes and potential intermediate allocations.
**Action:** Prioritize single-pass iterations (e.g., using `forEach` or `fold`) to calculate multiple aggregate values simultaneously to optimize performance and prevent redundant iterations.
