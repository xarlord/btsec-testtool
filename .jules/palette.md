## 2026-02-07 - Implement 'Done' keyboard action to submit Authorization screen form
**Learning:** For forms inside Jetpack Compose, handling `keyboardActions` (e.g., `onDone`) with `LocalFocusManager.current.clearFocus()` significantly improves accessibility and UX by allowing submission directly from the software keyboard without requiring users to explicitly dismiss the keyboard and find the physical button on the screen.
**Action:** Consistently set `KeyboardOptions(imeAction = ImeAction.Done)` and map `onDone` to form submission logic for terminal text inputs while ensuring keyboard dismissal via `clearFocus()`.
## 2026-02-07 - Add clear button to search inputs
**Learning:** For long text search fields, such as those inside HexDump and PacketTimeline screens, adding a trailing `IconButton` to quickly clear the input drastically improves user experience by saving them from deleting characters manually.
**Action:** When creating text fields meant for filtering or searching, include a trailing `IconButton` with `Icons.Default.Cancel` or `Icons.Default.Clear` that resets the search query and clears focus when the input is not empty.
## 2026-02-07 - Add clear button to Authorization input
**Learning:** For critical input fields like authorization or login screens, providing a quick way to clear the entire input via a trailing `IconButton` improves the user experience, especially on mobile devices where deleting long strings character-by-character is tedious.
**Action:** When designing text inputs that expect medium-to-long strings (like authorization codes or tokens), always include a trailing `IconButton` with `Icons.Default.Cancel` that resets the input state and clears focus, visible only when the input is not empty.
