## 2024-06-04 - Optimize Jetpack Compose Lists

**Learning:** When using Jetpack Compose lists (`LazyColumn` or `LazyRow`), omitting a `key` parameter can lead to unnecessary and expensive recompositions when the items list changes, as the framework cannot easily track item movement.
**Action:** Always provide a stable, unique `key` parameter (e.g., `key = { it.address }` or `key = { it.id }`) to `items()` inside `LazyColumn` or `LazyRow` to prevent unnecessary and expensive recompositions.
