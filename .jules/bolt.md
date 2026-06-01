## 2024-05-24 - LazyColumn Key Optimization
**Learning:** In Jetpack Compose, dynamic lists in `LazyColumn` or `LazyRow` can cause severe performance issues (unnecessary recompositions of all items) when the list changes (e.g. elements are inserted/removed/reordered) if a stable, unique `key` parameter is not provided. Without a key, Compose uses the item's position, leading to expensive UI updates as items shift.
**Action:** Always provide a unique `key` (e.g., `key = { it.address }`) to `items()` inside `LazyColumn` or `LazyRow` to optimize recompositions when rendering dynamic lists.
