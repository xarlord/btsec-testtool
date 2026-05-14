## 2023-10-27 - Collection Optimization
**Learning:** In FuzzingRepositoryImpl, calculating statistics was using multiple passes (sumOf) over the results collection.
**Action:** Replaced multiple sumOf calls with a single pass loop to calculate all metrics at once, reducing iteration count and overhead.
