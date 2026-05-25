## 2024-06-25 - Stable Keys in LazyColumn
**Learning:** In Compose, dynamic lists like `LazyColumn` without a stable `key` parameter can lead to unnecessary, expensive recompositions during frequent updates, especially with complex items.
**Action:** Always provide a stable, unique `key` parameter (e.g., `key = { it.address }`) to `items()` inside `LazyColumn` or `LazyRow` to prevent UI jank.
