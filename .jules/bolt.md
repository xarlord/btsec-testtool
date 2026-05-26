## 2024-05-24 - Optimize Jetpack Compose list rendering
**Learning:** Dynamic lists in Jetpack Compose (LazyColumn, LazyRow) trigger expensive unnecessary recompositions if items are inserted, deleted, or reordered without a stable unique `key`.
**Action:** Always provide a stable, unique `key` parameter to `items()` inside `LazyColumn` or `LazyRow` to prevent unnecessary recompositions when dynamic lists change.
