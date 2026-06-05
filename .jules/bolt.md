## 2024-06-02 - Optimize ScannerScreen LazyColumn
**Learning:** Added `key = { it.address }` to `items(devices)` in Jetpack Compose's `LazyColumn` to provide a stable identity for each list item, preventing unnecessary recompositions.
**Action:** Always provide a stable, unique key parameter to `items()` inside `LazyColumn` or `LazyRow` to prevent unnecessary and expensive recompositions when dynamic lists change.
