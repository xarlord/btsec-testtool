## 2024-05-01 - Single-Pass Collection Aggregation
**Learning:** Performing multiple terminal operations (`sumOf`, `average`, `maxByOrNull`) over collections scales poorly and allocates redundant intermediate iterators. Single-pass loops or `fold` can dramatically reduce this.
**Action:** Optimize statistical summaries (e.g. FuzzingStatistics) by replacing chained `.sumOf`/`.min`/`.max` blocks with a single iteration fold pattern.
