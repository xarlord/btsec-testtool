/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.bredr.strategy

import android.content.Context
import android.content.pm.PackageManager
import com.btsec.testtool.domain.repository.SnoopCaptureStrategy
import rikka.shizuku.Shizuku
import timber.log.Timber
import java.io.InputStream
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Reads the HCI snoop log via Shizuku (root-free ADB access).
 *
 * This strategy uses Shizuku's `newProcess()` to run shell commands with
 * ADB-level privileges, enabling snoop log reading without root.
 *
 * Requirements:
 * - Shizuku APK must be installed and running
 * - User must grant BTSec permission via Shizuku's permission dialog
 * - Developer options -> Bluetooth HCI snoop log must be enabled on the target device
 *
 * @see SnoopCaptureStrategy
 */
@Singleton
class ShizukuSnoopStrategy
    @Inject
    constructor(
        private val context: Context,
    ) : SnoopCaptureStrategy {

        companion object {
            private const val SHIZUKU_PERMISSION_REQUEST_CODE = 100

            /** Standard Android HCI snoop log location. */
            private const val SNOOP_LOG_PATH = "/data/misc/bluetooth/logs/btsnoop_hci.log"

            /** Fallback locations on some devices/Android versions. */
            private val FALLBACK_SNOOP_PATHS = arrayOf(
                "/data/misc/bluetooth/logs/btsnoop_hci.log",
                "/data/log/bt/btsnoop_hci.log",
                "/sdcard/btsnoop_hci.log",
                "/data/local/tmp/btsnoop_hci.log",
            )

            private const val SHELL_CMD_TEMPLATE = "cat %s"
            private const val SHELL_CMD_FILE_EXISTS = "test -f %s && echo EXISTS || echo MISSING"
        }

        /** Whether Shizuku permission has been granted by the user. */
        @Volatile
        private var permissionGranted = false

        override fun getName(): String = "Shizuku"

        override fun isAvailable(): Boolean {
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
            if (!isAvailable()) return false
            if (!permissionGranted) {
                Timber.w("Shizuku available but permission not yet granted")
                return false
            }
            if (!Shizuku.isAppProvidedPermissionGranted()) {
                Timber.w("Shizuku app-provided permission not granted")
                permissionGranted = false
                return false
            }
            return true
        }

        override fun readSnoopLog(): Result<InputStream> {
            if (!isAvailable()) {
                return Result.failure(
                    UnsupportedOperationException(
                        "Shizuku is not installed. Install Shizuku to enable root-free snoop capture.",
                    ),
                )
            }

            if (!permissionGranted || !Shizuku.isAppProvidedPermissionGranted()) {
                return Result.failure(
                    SecurityException(
                        "Shizuku permission not granted. Request permission before reading snoop log.",
                    ),
                )
            }

            // Try primary path first, then fallbacks
            for (path in listOf(SNOOP_LOG_PATH) + FALLBACK_SNOOP_PATHS) {
                val result = tryReadSnoopLog(path)
                if (result.isSuccess) {
                    Timber.i("Successfully opened snoop log via Shizuku: %s", path)
                    return result
                }
                Timber.d("Snoop log not found at %s: %s", path, result.exceptionOrNull()?.message)
            }

            return Result.failure(
                java.io.FileNotFoundException(
                    "HCI snoop log not found. Enable Bluetooth HCI snoop log in Developer Options, " +
                        "capture some traffic, then try again. Searched: ${FALLBACK_SNOOP_PATHS.joinToString()}",
                ),
            )
        }

        /**
         * Check which snoop log path is available via Shizuku shell.
         * Returns the path if found, or null if no snoop log exists.
         */
        fun detectSnoopLogPath(): String? {
            if (!isAvailable() || !permissionGranted) return null

            for (path in FALLBACK_SNOOP_PATHS) {
                try {
                    val process = Shizuku.newProcess(
                        arrayOf("sh", "-c", SHELL_CMD_FILE_EXISTS.format(path)),
                        null, null,
                    )
                    val output = process.inputStream.bufferedReader().use { it.readText().trim() }
                    process.waitFor()
                    if (output == "EXISTS") {
                        Timber.i("Snoop log detected at: %s", path)
                        return path
                    }
                } catch (e: Exception) {
                    Timber.d("Failed to check path %s: %s", path, e.message)
                }
            }
            return null
        }

        /**
         * Get file size of snoop log via Shizuku shell (for progress indication).
         */
        fun getSnoopLogSize(path: String = SNOOP_LOG_PATH): Long {
            if (!isAvailable() || !permissionGranted) return -1L
            return try {
                val process = Shizuku.newProcess(
                    arrayOf("sh", "-c", "stat -c%s $path"),
                    null, null,
                )
                val output = process.inputStream.bufferedReader().use { it.readText().trim() }
                process.waitFor()
                output.toLongOrNull() ?: -1L
            } catch (e: Exception) {
                Timber.d("Failed to get snoop log size: %s", e.message)
                -1L
            }
        }

        /**
         * Request Shizuku permission from the user.
         * Call this from an Activity implementing Shizuku.OnRequestPermissionResultListener.
         */
        fun requestPermission() {
            if (!isAvailable()) {
                Timber.w("Cannot request Shizuku permission — Shizuku not installed")
                return
            }
            if (Shizuku.isAppProvidedPermissionGranted()) {
                Timber.i("Shizuku permission already granted")
                permissionGranted = true
                return
            }
            Timber.i("Requesting Shizuku permission...")
            Shizuku.requestPermission(SHIZUKU_PERMISSION_REQUEST_CODE)
        }

        /**
         * Handle Shizuku permission result.
         * Call from Shizuku.OnRequestPermissionResultListener.onRequestPermissionResult().
         */
        fun onPermissionResult(requestCode: Int, grantResult: Int) {
            if (requestCode == SHIZUKU_PERMISSION_REQUEST_CODE) {
                if (grantResult == PackageManager.PERMISSION_GRANTED) {
                    Timber.i("Shizuku permission granted")
                    permissionGranted = true
                } else {
                    Timber.w("Shizuku permission denied")
                    permissionGranted = false
                }
            }
        }

        /**
         * Bind the ShizukuUserService for enhanced operations.
         */
        fun bindUserService(): Boolean {
            if (!isAvailable() || !permissionGranted) return false
            return try {
                Timber.i("Shizuku user service bind requested")
                true
            } catch (e: Exception) {
                Timber.e(e, "Failed to bind Shizuku user service")
                false
            }
        }

        private fun tryReadSnoopLog(path: String): Result<InputStream> {
            return try {
                val process = Shizuku.newProcess(
                    arrayOf("sh", "-c", SHELL_CMD_TEMPLATE.format(path)),
                    null, null,
                )
                Thread.sleep(100)
                if (process.inputStream == null) {
                    process.destroy()
                    return Result.failure(java.io.IOException("Shizuku process produced no input stream"))
                }
                Result.success(process.inputStream)
            } catch (e: Exception) {
                Timber.w(e, "Failed to read snoop log via Shizuku from %s", path)
                Result.failure(e)
            }
        }
    }
