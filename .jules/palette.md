
## 2024-05-18 - Authorization Screen Keyboard Usability
**Learning:** Adding `keyboardOptions` with `ImeAction.Done` and a `keyboardActions` handler with `onDone` to an `OutlinedTextField` provides a significant micro-UX improvement. It allows users to submit the form directly from their software keyboard, making the interaction feel seamless and intuitive, especially for single-input screens like the Authorization Screen.
**Action:** Actively look for forms or single-input fields where this pattern can be applied. Ensure the `onDone` handler checks for valid input and non-loading states before triggering the submission action.
