## 2026-05-04 - Optimize Collection Traversals in Repository Tier
**Learning:** Kotlin collection extensions like `.filter`, `.count`, `.map`, and `.maxByOrNull` chained together create intermediate allocations and require multiple O(N) traversals. In tight loops or large datasets, this becomes a performance bottleneck.
**Action:** Use a single-pass `forEach` or `fold` to aggregate statistics over collections. This prevents redundant intermediate allocations and limits traversal overhead to exactly one pass.
