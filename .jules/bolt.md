## 2024-05-03 - Avoid Multiple Terminal Operations on Collections
**Learning:** Found a pattern in repositories (e.g., FuzzingRepositoryImpl, ReportRepositoryImpl) where statistical aggregation over long-running lists was repeatedly using multiple terminal operations (`sumOf`, `count`, `map`) instead of a single-pass loop. This results in unnecessary, redundant list iterations and intermediate object allocations.
**Action:** Use a single-pass `forEach` or `fold` over collections when collecting multiple statistics simultaneously to avoid redundant list traversal and optimize performance.
