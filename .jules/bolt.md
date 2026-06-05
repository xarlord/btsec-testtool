## YYYY-MM-DD - [Title]
**Learning:** [Insight]
**Action:** [How to apply next time]
## 2026-02-09 - Jetpack Compose LazyColumn Optimization
**Learning:** In Bluetooth scanning applications, the device list updates extremely frequently. Without a stable `key` parameter, `LazyColumn` will recompose the entire list on every emission, causing significant UI jank and CPU overhead.
**Action:** Always provide a stable, unique `key` (like MAC `address`) to `items()` inside `LazyColumn` or `LazyRow` to prevent unnecessary recompositions when dynamic lists change.
