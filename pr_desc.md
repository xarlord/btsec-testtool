💡 What
Added KeyboardOptions (ImeAction.Done) and KeyboardActions (onDone) to the OutlinedTextField in the AuthorizationScreen.

🎯 Why
Allows users to directly submit their Authorization ID from the software keyboard, creating a smoother interaction compared to manually dismissing the keyboard and pressing the verification button.

📸 Before/After
Before: The enter key on the soft keyboard just adds a newline or dismisses the keyboard, requiring the user to tap the "Verify" button explicitly.
After: The soft keyboard displays a "Done" action button that dismisses the keyboard and automatically triggers the verification process (using the exact same validation logic as the button).

♿ Accessibility
Improves accessibility for users relying heavily on keyboard navigation or single-switch access by minimizing the steps required to submit the form.
