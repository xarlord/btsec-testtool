/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.bredr.strategy

import com.btsec.testtool.domain.repository.SnoopCaptureStrategy
import timber.log.Timber
import java.io.InputStream
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Placeholder strategy for reading the HCI snoop log via Shizuku.
 *
 * **This is a placeholder implementation.** Shizuku dependencies have NOT been
 * added yet (they are large and need careful versioning). When Shizuku is
 * integrated, this class should be updated to:
 *
 * 1. Check for Shizuku availability via `Shizuku.checkSelfPermission()` /
 *    `Shizuku.isAppProvidedPermissionGranted()`
 * 2. Request permission via `Shizuku.requestPermission()`
 * 3. Use `Shizuku.newProcess(arrayOf("su", "-c", "cat ..."), ...)` or a
 *    Shizuku `IUserService` to execute a shell command that reads the snoop log
 * 4. Return the command stdout as an [InputStream]
 *
 * The Shizuku approach provides root-free snoop capture by transpiling calls
 * through ADB-level permissions (the user must have Shizuku running and grant
 * permission to this app).
 *
 * Required dependencies (to be added later):
 * ```kotlin
 * implementation("rikka.shizuku:api:13.1.5")
 * implementation("rikka.shizuku:provider:13.1.5")
 * ```
 *
 * See: docs/Shizuku-RootFree-Snoop-Capture.md
 * Issues: #375 (root-free snoop capture), #412 (strategy pattern refactor)
 */
@Singleton
class ShizukuSnoopStrategy @Inject constructor() : SnoopCaptureStrategy {

    override fun getName(): String = "Shizuku"

    override fun isAvailable(): Boolean {
        // TODO: Replace with Shizuku.checkSelfPermission() once Shizuku lib is added.
        //   For now, detect Shizuku by checking if the class can be loaded.
        return try {
            Class.forName("rikka.shizuku.Shizuku")
            Timber.i("Shizuku class found — Shizuku APK is installed")
            true
        } catch (e: ClassNotFoundException) {
            Timber.d("Shizuku not available — APK not installed")
            false
        }
    }

    override fun canReadSnoopLog(): Boolean {
        // TODO: Once Shizuku lib is integrated, check:
        //   1. Shizuku.isAppProvidedPermissionGranted()
        //   2. Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED
        //   3. ShizukuService is running
        if (!isAvailable()) return false

        Timber.w("Shizuku strategy: canReadSnoopLog() not yet implemented — " +
            "Shizuku library dependencies not added")
        return false
    }

    override fun readSnoopLog(): Result<InputStream> {
        if (!isAvailable()) {
            return Result.failure(
                UnsupportedOperationException(
                    "Shizuku is not installed. Install Shizuku to enable root-free snoop capture.",
                ),
            )
        }

        // TODO: Implement using Shizuku API:
        //   val process = Shizuku.newProcess(
        //       arrayOf("cat", DirectFileSnoopStrategy.SNOOP_LOG_PATH),
        //       null, null
        //   )
        //   return Result.success(process.inputStream)
        Timber.w("Shizuku strategy: readSnoopLog() not yet implemented — " +
            "Shizuku library dependencies not added")
        return Result.failure(
            UnsupportedOperationException(
                "Shizuku-based snoop reading is not yet implemented. " +
                    "See docs/Shizuku-RootFree-Snoop-Capture.md for the integration plan.",
            ),
        )
    }
}
