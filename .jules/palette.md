## 2024-05-15 - Improve Form Accessibility with Keyboard Actions
**Learning:** Configuring keyboardOptions and keyboardActions (like ImeAction.Done) in Compose forms enhances UX by allowing users to submit forms directly from the software keyboard without needing to tap the screen button.
**Action:** Always include keyboard action handlers in text inputs and remember to explicitly call LocalFocusManager.current.clearFocus() within the action to dismiss the keyboard.
