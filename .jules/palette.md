## 2026-02-07 - Compose Text Input Keyboard Actions
**Learning:** Adding keyboard actions (ImeAction.Done) to text fields without mirroring the validation logic of the primary submit button can bypass validation constraints.
**Action:** When adding `keyboardActions = KeyboardActions(onDone = { ... })`, ensure you call `LocalFocusManager.current.clearFocus()` to dismiss the keyboard, and always wrap the submission logic in the exact same `if (isValid && !isLoading)` conditions used by the main button.
