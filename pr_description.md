💡 What
Added a unique `key` parameter to the `items()` method for rendering the `topVulnerableDevices` list in the `AnalyticsScreen`.

🎯 Why
Jetpack Compose's `LazyColumn` dynamically manages list items. Without a stable, explicit `key`, Compose relies on item positions. When the list changes, this can trigger excessive recompositions across multiple list items, leading to degraded scrolling and rendering performance, especially with dynamic data. Providing `key = { it.deviceAddress }` ensures stable identity tracking.

📊 Impact
Reduces unnecessary recompositions of `DeviceRiskCard` items when the underlying list of top vulnerable devices updates or when items are added/removed.

🔬 Measurement
Can be verified by monitoring the Compose Recomposition counts using the Android Studio Layout Inspector while the `AnalyticsScreen` dynamically updates its device list. The `DeviceRiskCard` components should show zero recompositions for items whose data has not actually changed.
