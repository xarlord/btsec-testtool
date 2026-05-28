## 2024-05-28 - Keyboard action for Authorization Screen
**Learning:** Adding IME keyboard actions to TextFields (like `ImeAction.Done` and `keyboardActions`) improves UX by allowing users to submit forms directly from their software keyboard, without needing to dismiss the keyboard and find the physical submit button on screen.
**Action:** When creating text inputs that act as a single or final input before submission, configure `KeyboardOptions(imeAction = ImeAction.Done)` and `KeyboardActions(onDone = { ... })` to trigger the submit action and clear focus via `LocalFocusManager`.
