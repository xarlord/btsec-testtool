## 2026-04-20 - Added Loading State to Scanner
**Learning:** The ScannerScreen displayed a confusing blank state while actively scanning for devices before finding any. Implementing a proper loading state (CircularProgressIndicator + text) when 'isScanning' is true but the device list is empty provides immediate feedback that the app is working.
**Action:** When building scanning or search screens, always ensure there is a clear visual distinction between the initial empty state, the active searching/loading state, and the 'no results found' state.
