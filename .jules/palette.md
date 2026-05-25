## 2026-02-07 - Add Keyboard Actions for Authentication Form
**Learning:** Adding `KeyboardOptions` (e.g. `ImeAction.Done`) and `KeyboardActions` inside single-field input screens drastically improves UX by allowing form submission directly from the soft keyboard. It is critical to include validation (`isValid && !isLoading`) exactly like the primary submit button to avoid bypassing constraints.
**Action:** Always include keyboard submission shortcuts on primary single-input form fields.
