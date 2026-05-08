## 2026-05-08 - Software Keyboard Navigation for Forms
**Learning:** In Jetpack Compose, forms that lack `KeyboardOptions` and `KeyboardActions` force users to manually dismiss the software keyboard to find and press a submit button, creating friction and poor UX.
**Action:** Always configure `KeyboardOptions` (e.g., `imeAction = ImeAction.Done`) and `KeyboardActions` (e.g., `onDone`) on the final text input of a form to allow seamless, accessible submission directly from the keyboard.
