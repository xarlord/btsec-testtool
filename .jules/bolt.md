## 2024-05-22 - Add stable keys to LazyColumn items
**Learning:** In Jetpack Compose, dynamic lists (like Bluetooth scanning results) without unique keys in `items()` cause unnecessary and expensive recompositions of all items when the list changes.
**Action:** Always provide a stable, unique `key` parameter (e.g., `key = { it.address }`) to `items()` inside `LazyColumn` or `LazyRow` to prevent these unnecessary recompositions.
