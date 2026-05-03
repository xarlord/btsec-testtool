## 2026-02-07 - Improved Authentication Flow UX
**Learning:** Adding KeyboardOptions and KeyboardActions to the authentication token input field allows users to initiate the verification process directly from their software keyboard, significantly smoothing the initial access experience.
**Action:** Apply `keyboardOptions(imeAction = ImeAction.Done)` and `keyboardActions(onDone = { ... })` on terminal input fields for streamlined form submissions.
