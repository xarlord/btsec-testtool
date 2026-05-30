💡 What
Added a unique `key` parameter to the `items` call within the `LazyColumn` in `ScannerScreen.kt`.

🎯 Why
By default, Jetpack Compose uses the item's position as the key for lists. When the list of scanned Bluetooth devices changes dynamically (e.g. devices added, removed, or reordered), Compose has to re-evaluate and potentially re-render all list items because it cannot uniquely identify them. Using `device.address` as a stable key allows Compose to efficiently map list data to components and avoid unnecessary recompositions.

📊 Impact
Reduces unnecessary UI recompositions in `ScannerScreen` when new devices are discovered or the list updates, saving CPU cycles and improving scrolling performance, especially when there are many devices nearby.

🔬 Measurement
Verify using Compose Compiler Metrics or Layout Inspector to observe that only newly added/modified items trigger recomposition during an active Bluetooth scan.
