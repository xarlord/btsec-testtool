## 2024-05-24 - Compose List Recomposition
**Learning:** Jetpack Compose `LazyColumn` and `LazyRow` items without explicit `key` parameters can cause excessive recomposition when the list content changes, negatively impacting performance.
**Action:** Always provide a stable, unique `key` parameter to `items()` inside `LazyColumn` or `LazyRow` based on the item's identity (e.g. `key = { it.id }` or `key = { it.deviceAddress }`).
