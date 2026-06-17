💡 What
Added a "Clear" (`Cancel`) `IconButton` as a trailing icon to the Authorization ID text field on the `AuthorizationScreen`.

🎯 Why
To improve the user experience by allowing users to quickly clear the Authorization ID input field with a single tap, rather than having to manually delete a long string of characters (e.g., `BTSEC-20260207-A1B2C3D4`).

📸 Before/After
Before: The OutlinedTextField only contained the text input.
After: The OutlinedTextField includes a trailing "X" icon when there is text present, which clears the input when tapped.

♿ Accessibility
Included a descriptive `contentDescription = "Clear authorization ID"` to the `IconButton` to ensure screen reader users are informed of the button's action.
