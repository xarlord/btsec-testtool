## 2026-02-07 - Add unique keys to Jetpack Compose LazyColumn items
**Learning:** In Jetpack Compose, dynamic lists inside `LazyColumn` or `LazyRow` can cause expensive and unnecessary recompositions when the list changes if items lack a stable, unique `key`.
**Action:** Always provide a stable `key` parameter to `items()` (e.g., `key = { it.address }`) when displaying dynamic data to improve rendering performance.
