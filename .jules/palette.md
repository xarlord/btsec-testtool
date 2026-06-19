## 2026-02-07 - Implement 'Done' keyboard action to submit Authorization screen form
**Learning:** For forms inside Jetpack Compose, handling `keyboardActions` (e.g., `onDone`) with `LocalFocusManager.current.clearFocus()` significantly improves accessibility and UX by allowing submission directly from the software keyboard without requiring users to explicitly dismiss the keyboard and find the physical button on the screen.
**Action:** Consistently set `KeyboardOptions(imeAction = ImeAction.Done)` and map `onDone` to form submission logic for terminal text inputs while ensuring keyboard dismissal via `clearFocus()`.
## 2026-02-07 - Add clear button to search inputs
**Learning:** For long text search fields, such as those inside HexDump and PacketTimeline screens, adding a trailing `IconButton` to quickly clear the input drastically improves user experience by saving them from deleting characters manually.
**Action:** When creating text fields meant for filtering or searching, include a trailing `IconButton` with `Icons.Default.Cancel` or `Icons.Default.Clear` that resets the search query and clears focus when the input is not empty.
## 2026-02-12 - Adding Clear Buttons to Text Inputs
**Learning:** In Jetpack Compose, when adding a clear `IconButton` as a `trailingIcon` to an `OutlinedTextField` or similar input component, it is important to wrap the button in a condition (e.g., `if (text.isNotEmpty())`) so the cancel icon is only visible when there is actual text to clear, improving UX. Also, remember to import both `Icons.Default.Cancel` and `IconButton`.
**Action:** Next time I add clear buttons to text fields, I will ensure they are conditionally rendered based on the text length and verify all required imports.
