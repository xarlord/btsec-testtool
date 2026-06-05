## 2026-05-24 - Provide Stable Keys for LazyColumn
**Learning:** Jetpack Compose `LazyColumn` items without a stable key will unnecessarily and expensively recompose when list data changes (e.g., dynamic Bluetooth device scanning).
**Action:** Always provide a stable, unique `key` parameter to `items()` inside `LazyColumn` or `LazyRow` to eliminate performance bottlenecks during dynamic list updates.
