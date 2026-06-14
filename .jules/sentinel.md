## 2026-06-08 - EncryptedSharedPreferences Auto-Backup Crash
**Vulnerability:** Application crashes on restore due to corrupted EncryptedSharedPreferences.
**Learning:** EncryptedSharedPreferences uses a Keystore key permanently bound to a device. When the file is restored on a new device via Auto-Backup, the key doesn't transfer, and attempting to access the file throws a `GeneralSecurityException`.
**Prevention:** Always exclude the generated XML file from Android Auto Backup rules (`<exclude domain="sharedpref" path="..." />` in `backup_rules.xml`) and wrap initialization in a `try-catch` to clear the file on failure.
