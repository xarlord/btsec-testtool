## 2026-06-08 - EncryptedSharedPreferences Auto-Backup Crash
**Vulnerability:** Application crashes on restore due to corrupted EncryptedSharedPreferences.
**Learning:** EncryptedSharedPreferences uses a Keystore key permanently bound to a device. When the file is restored on a new device via Auto-Backup, the key doesn't transfer, and attempting to access the file throws a `GeneralSecurityException`.
**Prevention:** Always exclude the generated XML file from Android Auto Backup rules (`<exclude domain="sharedpref" path="..." />` in `backup_rules.xml`) and wrap initialization in a `try-catch` to clear the file on failure.
## 2024-06-15 - Prevent EncryptedSharedPreferences backup crash
**Vulnerability:** Android 12+ cloud and device transfer backup rules did not exclude `secure_auth_prefs.xml`, an `EncryptedSharedPreferences` file.
**Learning:** `EncryptedSharedPreferences` uses a Master Key stored in the Android Keystore, which is hardware-bound. If this XML file is backed up and restored to a different device, the app will crash with a `SecurityException` upon launch, causing a persistent DoS until app data is cleared.
**Prevention:** Always add explicit exclusion rules for `EncryptedSharedPreferences` files in both `backup_rules.xml` (for older Android versions) AND `data_extraction_rules.xml` (for Android 12+).
