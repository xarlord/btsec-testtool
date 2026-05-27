## 2026-02-07 - Add unique keys to Jetpack Compose LazyColumn items
**Learning:** Using `items(list)` in dynamic `LazyColumn` without a `key` parameter causes Jetpack Compose to recompose items unnecessarily as the underlying list changes positionally, leading to degraded scrolling and rendering performance when heavily updated (e.g. active Bluetooth scanning).
**Action:** Always provide a stable, unique `key` parameter (like `it.address`) in Jetpack Compose `LazyColumn` and `LazyRow` dynamic list iterators to minimize expensive recompositions.
