## 2024-03-02 - Keyboard UX improvement
**Learning:** Adding keyboard actions (`keyboardActions = KeyboardActions(onDone = { ... })`) to a text input allows users to submit the form directly from the keyboard without having to click the button. Additionally, dismissing the keyboard when the user submits (`LocalFocusManager.current.clearFocus()`) provides a smoother experience.
**Action:** Always consider keyboard navigation for forms to enhance UX.
