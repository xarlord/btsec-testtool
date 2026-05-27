## 2024-05-27 - Keyboard Submission Optimization in Jetpack Compose
**Learning:** In Jetpack Compose, forms require explicit `keyboardOptions` and `keyboardActions` for text fields to allow users to submit directly from the software keyboard, significantly improving mobile UX compared to forcing them to tap a separate button.
**Action:** Always configure `keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done)` and bind `keyboardActions` (with `LocalFocusManager.current.clearFocus()`) to the main submit action for critical form inputs.
