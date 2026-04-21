## 2024-04-21 - Optimize Statistical Aggregations
**Learning:** Found multiple instances where statistical functions chained terminal operations (e.g., `sumOf`, `maxByOrNull`, `filter`) over large collections. This creates a time complexity of O(n * k) and causes unnecessary intermediate list allocations, which can lead to memory overhead on Android devices.
**Action:** Always refactor statistical aggregations over collections to prioritize single-pass iterations (e.g., using `forEach` or `fold`). This ensures O(n) performance and eliminates intermediate objects.
