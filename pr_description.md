💡 What
Added the `key` parameter to `items()` calls within `LazyColumn`s across multiple screens (`VulnScannerScreen.kt`, `ScannerScreen.kt`, `KeyExtractionScreen.kt`, `FuzzerScreen.kt`).

🎯 Why
By default, Jetpack Compose uses the item's position in the list as its key. When lists are dynamic (items added, removed, or reordered), this causes Compose to unnecessarily recompose items that merely shifted position, which degrades scroll performance and can cause state loss for complex list items. Providing a stable, unique key (like an ID or MAC address) allows Compose to track items accurately and avoid these expensive re-renders.

📊 Impact
Prevents unnecessary recompositions of complex `Card` and `DeviceCard` components when the backing list changes. This leads to smoother scrolling and lower CPU usage, especially noticeable during active scans or when large lists of vulnerabilities/fuzzing findings are updated in real-time.

🔬 Measurement
Verify by enabling the Layout Inspector with "Show Recomposition Counts" in Android Studio and observing the significantly reduced recomposition counts on list items when new devices or findings are appended to the lists during a scan.
