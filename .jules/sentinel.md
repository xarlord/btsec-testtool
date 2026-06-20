## 2026-06-08 - EncryptedSharedPreferences Auto-Backup Crash
**Vulnerability:** Application crashes on restore due to corrupted EncryptedSharedPreferences.
**Learning:** EncryptedSharedPreferences uses a Keystore key permanently bound to a device. When the file is restored on a new device via Auto-Backup, the key doesn't transfer, and attempting to access the file throws a `GeneralSecurityException`.
**Prevention:** Always exclude the generated XML file from Android Auto Backup rules (`<exclude domain="sharedpref" path="..." />` in `backup_rules.xml`) and wrap initialization in a `try-catch` to clear the file on failure.
## 2026-06-08 - Development bypass left in production
**Vulnerability:** Authorization bypass. The `AuthorizationUseCase` class was hardcoded to always return true for `verifyAuthorization`, `isActionAuthorized`, and `isTargetInScope` using a "BYPASS MODE". This completely circumvents the authorization enforcement.
**Learning:** Development bypasses or hardcoded "always return true" flags can be accidentally left in the code.
**Prevention:** Never leave hardcoded bypass logic in security-critical paths.
