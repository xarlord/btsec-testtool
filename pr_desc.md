🚨 Severity: CRITICAL
💡 Vulnerability: Application crashes on restore due to corrupted `EncryptedSharedPreferences`. `EncryptedSharedPreferences` uses a Keystore key permanently bound to a device. When the file is restored on a new device via Auto-Backup, the key doesn't transfer, and attempting to access the file throws a `GeneralSecurityException`.
🎯 Impact: This crashes the application when a user restores their device from a backup, completely breaking the application for them.
🔧 Fix: Added `secure_auth_prefs.xml` to `data_extraction_rules.xml` to exclude it from Android 12+ cloud backup and device transfer.
✅ Verification: Ensure tests pass and the `secure_auth_prefs.xml` is listed in `<cloud-backup>` and `<device-transfer>` sections of `data_extraction_rules.xml`.
