## 2026-02-09 - Improve form submission UX with keyboard actions
**Learning:** Configuring keyboardOptions (imeAction = ImeAction.Done) and keyboardActions allows users to submit forms directly from the software keyboard without needing to explicitly dismiss the keyboard and tap the submit button.
**Action:** Always provide keyboard submit actions for single-input forms and ensure the same validation logic is applied as the main submit button. Remember to clear focus using LocalFocusManager.current.clearFocus() within the action.
