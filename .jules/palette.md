## 2024-05-18 - [Submit Form from Keyboard in Compose]
**Learning:** Users expect to be able to submit single-input forms directly from the software keyboard, but Compose TextFields don't configure this by default.
**Action:** Always configure keyboardOptions (e.g., imeAction = ImeAction.Done) and keyboardActions (e.g., onDone) to explicitly dismiss the keyboard (using LocalFocusManager) and submit the form.
