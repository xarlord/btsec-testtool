# HCI Snoop Log Root-Free Implementation

**Issue:** #405
**Status:** Design Document
**Priority:** HIGH

## Problem

The current `SnoopCaptureRepositoryImpl` reads `/data/misc/bluetooth/logs/btsnoop_hci.log` which requires root access. This blocks usage on non-rooted devices (majority of users).

## Proposed Solutions

### Solution 1: Shizuku Integration (Recommended)

**Overview:**
Shizuku allows apps to execute adb commands with proper permissions without requiring root.

**Implementation Steps:**

1. **Add Shizuku Dependency**
   ```kotlin
   // app/build.gradle.kts
   implementation("rikka.shizuku:api:13.1.5")
   implementation("rikka.shizuku:provider:13.1.5")
   ```

2. **Create Shizuku Snoop Capture Implementation**
   ```kotlin
   class SnoopCaptureShizukuImpl @Inject constructor(
       @ApplicationContext private val context: Context,
       private val snoopCaptureUseCase: SnoopCaptureUseCase
   ) : SnoopCaptureRepository {

       private fun checkShizukuPermission(): Boolean {
           if (!Shizuku.isAppProvidedPermissionGranted()) {
               // Request Shizuku permission
               Shizuku.addRequestPermissionResultListener { _, grantResult ->
                   if (grantResult == PackageManager.PERMISSION_GRANTED) {
                       // Permission granted
                   }
               }
               Shizuku.requestPermission(0)
               return false
           }
           return true
       }

       override suspend fun readNewRecords(file: File): List<SnoopRecord> {
           if (!checkShizukuPermission()) {
               return emptyList()
           }

           // Use adb shell to read snoop log
           val process =
               Runtime.getRuntime().exec(
                   arrayOf(
                       "adb",
                       "shell",
                       "su",
                       "-c",
                       "cat /data/misc/bluetooth/logs/btsnoop_hci.log"
                   )
               )
           // Parse output...
       }
   }
   ```

3. **User Prompt**
   - Show dialog when snoop capture is requested
   - Explain Shizuku requirement
   - Link to Shizuku setup instructions
   - Enable alternative methods (ADB bugreport)

### Solution 2: ADB Bugreport Extraction

**Overview:**
Extract snoop logs from `adb bugreport` zip files.

**Implementation:**
```kotlin
suspend fun extractFromBugreport(zipFile: File): List<SnoopRecord> {
    val snoopEntry = ZipFile(zipFile).getEntry("btsnoop_hci.log")
    // Extract and parse
}
```

**User Flow:**
1. User generates bugreport: `adb bugreport report.zip`
2. User uploads zip file in app
3. App extracts snoop log and parses

### Solution 3: Native Packet Monitoring (Android 12+)

**Overview:**
Use Android's packet monitoring APIs if available.

**Implementation:**
```kotlin
if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
    // Check for packet monitoring capability
    val hasMonitor = bluetoothAdapter.isLe2mPhySupported
    // Use alternative if available
}
```

## Recommended Implementation Plan

### Phase 1: Shizuku Integration (Primary)
1. Add Shizuku dependencies
2. Create permission check UI
3. Implement Shizuku-based capture
4. Test on non-rooted device
5. Update user documentation

### Phase 2: Fallback Options
1. Implement bugreport extraction
2. Add file upload UI
3. Document manual process

### Phase 3: Native APIs (Future)
1. Research packet monitoring availability
2. Implement if supported
3. Fallback to Shizuku if not

## Files to Modify

- `app/build.gradle.kts` - Add Shizuku dependencies
- `app/src/main/java/com/btsec/testtool/data/bredr/SnoopCaptureRepositoryImpl.kt` - Refactor
- `app/src/main/java/com/btsec/testtool/data/bredr/SnoopCaptureShizukuImpl.kt` - New file
- `app/src/main/java/com/btsec/testtool/presentation/feature/settings/SettingsScreen.kt` - Add Shizuku setup
- Documentation files

## Testing Checklist

- [ ] Shizuku permission request flow
- [ ] Snoop log reading via Shizuku
- [ ] Fallback when Shizuku not available
- [ ] Bugreport extraction
- [ ] File upload and parsing
- [ ] Error handling and user feedback

## Documentation Updates

1. **README.md:**
   - Add Shizuku setup section
   - Document snoop log capture methods

2. **User Guide:**
   - How to install Shizuku
   - How to grant permissions
   - Alternative methods without Shizuku

3. **Security Considerations:**
   - Shizuku security model
   - Why this is safe (user-granted permission)
   - Comparison to root access

## References

- Shizuku GitHub: https://github.com/RikkaApps/Shizuku
- Shizuku API Docs: https://shizuku.rikka.app/
- Android HCI Snoop: https://source.android.com/devices/bluetooth/hci_snoop_logger

## Notes

This is a design document. The actual implementation should:
1. Handle all edge cases
2. Provide clear user feedback
3. Gracefully degrade when Shizuku unavailable
4. Maintain security model (no privilege escalation)
5. Follow Android best practices
