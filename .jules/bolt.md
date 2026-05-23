## 2024-05-23 - Stable Keys in LazyColumn
**Learning:** In Jetpack Compose, missing unique keys in `LazyColumn` items can cause expensive and unnecessary recompositions when elements in dynamic lists (like Bluetooth scanner results) change, are added, or removed.
**Action:** Always provide a stable, unique `key` parameter (e.g., `key = { it.address }`) to `items()` inside `LazyColumn` or `LazyRow` to optimize rendering performance.
