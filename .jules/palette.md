## 2026-02-07 - Implement Compose keyboard actions for form submission
**Learning:** In Jetpack Compose, forms lacking `KeyboardActions` force users to manually dismiss the soft keyboard and tap the submit button, degrading UX.
**Action:** Always configure `KeyboardOptions(imeAction = ImeAction.Done)` and `KeyboardActions(onDone = { ... })` on text inputs in forms, ensuring the completion action calls `LocalFocusManager.current.clearFocus()` and implements the exact same validation state as the primary submit button.
