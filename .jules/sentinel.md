## 2026-06-08 - EncryptedSharedPreferences Auto-Backup Crash
**Vulnerability:** Application crashes on restore due to corrupted EncryptedSharedPreferences.
**Learning:** EncryptedSharedPreferences uses a Keystore key permanently bound to a device. When the file is restored on a new device via Auto-Backup, the key doesn't transfer, and attempting to access the file throws a `GeneralSecurityException`.
**Prevention:** Always exclude the generated XML file from Android Auto Backup rules (`<exclude domain="sharedpref" path="..." />` in `backup_rules.xml`) and wrap initialization in a `try-catch` to clear the file on failure.
## 2026-02-07 - EncryptedSharedPreferences Backup Crash

**Vulnerability:** The `secure_auth_prefs.xml` file, which backs `EncryptedSharedPreferences`, was not excluded from Android 12+ cloud backups and device transfers in `data_extraction_rules.xml`.
**Learning:** `EncryptedSharedPreferences` relies on a Master Key in the Android Keystore that is hardware-bound. If the XML file is transferred to a new device without the key (which never transfers), the app will crash upon launch because it cannot decrypt the data.
**Prevention:** Always add the generated preference XML filename to both `backup_rules.xml` and `data_extraction_rules.xml` (under `<cloud-backup>` and `<device-transfer>`) to ensure it is never backed up or transferred.
