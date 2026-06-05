## 2024-05-31 - Jetpack Compose List Recomposition
**Learning:** Dynamic lists in Jetpack Compose (like Bluetooth scanning results) cause massive unnecessary recompositions when new items are added if a stable, unique `key` parameter is not provided to the `items()` function in `LazyColumn`.
**Action:** Always provide a stable unique key (e.g., `key = { it.address }`) to `items()` inside `LazyColumn` or `LazyRow` to prevent expensive UI re-renders.
