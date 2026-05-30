## 2026-02-07 - Initial setup
**Learning:** Initializing bolt journal.
**Action:** Use this file to record CRITICAL codebase-specific performance learnings.
## 2026-02-07 - Missing item key in LazyColumn
**Learning:** Found a missing key parameter in LazyColumn `items()` in `ScannerScreen.kt`. Without a key, Compose uses item position to match items during recomposition. If the list changes (items added, removed, reordered), Compose will re-evaluate and potentially re-render all items instead of just the changed ones, leading to performance issues especially with long dynamic lists.
**Action:** Always provide a stable, unique key parameter to `items()` inside `LazyColumn` or `LazyRow` to prevent unnecessary and expensive recompositions.
