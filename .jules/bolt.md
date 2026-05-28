## 2024-05-18 - Missing Keys in Jetpack Compose LazyColumn
**Learning:** Found a performance bottleneck where `items()` inside `LazyColumn` lacked a stable unique `key` parameter. This causes unnecessary recompositions for the entire list whenever a dynamic list (like live Bluetooth scan results) changes.
**Action:** Always provide a stable unique `key` parameter (e.g., `key = { it.address }`) to `items()` inside `LazyColumn` or `LazyRow` to prevent unnecessary and expensive recompositions.
