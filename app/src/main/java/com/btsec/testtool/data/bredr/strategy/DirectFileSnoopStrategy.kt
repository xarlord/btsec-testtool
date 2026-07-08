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
import java.io.File
import java.io.FileInputStream
import java.io.InputStream
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Strategy that reads the HCI snoop log directly from the filesystem.
 *
 * This is the original approach used by [SnoopCaptureRepositoryImpl].
 * It requires root access because the snoop log lives at
 * `/data/misc/bluetooth/logs/btsnoop_hci.log` which is owned by the
 * `bluetooth` system user (permissions 0660).
 *
 * This strategy is always "available" (the code path exists on every device),
 * but [canReadSnoopLog] will return false if the file is not readable without root.
 *
 * Issues: #375 (root-free snoop capture), #412 (strategy pattern refactor)
 */
@Singleton
class DirectFileSnoopStrategy
    @Inject
    constructor() : SnoopCaptureStrategy {
        companion object {
            /** Standard Android HCI snoop log path. */
            const val SNOOP_LOG_PATH = "/data/misc/bluetooth/logs/btsnoop_hci.log"
        }

        private val snoopFile = File(SNOOP_LOG_PATH)

        override fun getName(): String = "Direct File"

        override fun isAvailable(): Boolean {
            // The direct-file code path is always available on Android.
            // Whether the file is actually readable is checked by canReadSnoopLog().
            return true
        }

        override fun canReadSnoopLog(): Boolean {
            return try {
                snoopFile.exists() && snoopFile.canRead()
            } catch (e: SecurityException) {
                Timber.w(e, "Direct file snoop log not readable (expected without root)")
                false
            }
        }

        override fun readSnoopLog(): Result<InputStream> {
            return try {
                if (!snoopFile.exists()) {
                    return Result.failure(
                        FileNotFoundException("Snoop log not found at $SNOOP_LOG_PATH"),
                    )
                }
                if (!snoopFile.canRead()) {
                    return Result.failure(
                        SecurityException(
                            "Cannot read snoop log — root access required. " +
                                "Consider using Shizuku or bugreport strategy for root-free capture.",
                        ),
                    )
                }
                Result.success(FileInputStream(snoopFile))
            } catch (e: Exception) {
                Timber.w(e, "Failed to read snoop log via direct file strategy")
                Result.failure(e)
            }
        }
    }
