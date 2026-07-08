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
import java.io.BufferedInputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileNotFoundException
import java.io.InputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Strategy that extracts the HCI snoop log from an ADB bugreport zip file.
 *
 * The user generates a bugreport via `adb bugreport report.zip` and provides
 * the zip file to the app. This strategy then extracts the `btsnoop_hci.log`
 * entry from the zip and returns it as an [InputStream].
 *
 * Common entry paths inside bugreport zips:
 * - `btsnoop_hci.log` (older bugreports)
 * - `FS/data/misc/bluetooth/logs/btsnoop_hci.log` (newer bugreports)
 * - `bugreports/<device>/btsnoop_hci.log` (full bugreports)
 *
 * The strategy scans the zip for any entry whose name ends with
 * `btsnoop_hci.log`.
 *
 * **Note:** This is a one-shot strategy — the user provides a static zip file,
 * so it cannot be used for live monitoring. It's useful for post-capture analysis.
 *
 * Usage:
 * ```kotlin
 * val strategy = BugreportSnoopStrategy()
 * strategy.setBugreportZip("/path/to/bugreport.zip")
 * if (strategy.canReadSnoopLog()) {
 *     val result = strategy.readSnoopLog()
 *     result.getOrNull()?.use { stream -> ... }
 * }
 * ```
 *
 * Issues: #375 (root-free snoop capture), #412 (strategy pattern refactor)
 */
@Singleton
class BugreportSnoopStrategy
    @Inject
    constructor() : SnoopCaptureStrategy {
        /** The path to the bugreport zip file, set by the user. */
        @Volatile
        private var bugreportZipPath: String? = null

        /**
         * Set the path to the bugreport zip file.
         *
         * @param path Absolute path to the bugreport zip file.
         */
        fun setBugreportZip(path: String) {
            bugreportZipPath = path
            Timber.d("Bugreport strategy: zip path set to %s", path)
        }

        /**
         * Clear the bugreport zip path.
         */
        fun clearBugreportZip() {
            bugreportZipPath = null
        }

        override fun getName(): String = "Bugreport"

        override fun isAvailable(): Boolean {
            // The bugreport strategy is available as long as a zip path has been set
            // and the file exists.
            val path = bugreportZipPath ?: return false
            return File(path).exists()
        }

        override fun canReadSnoopLog(): Boolean {
            val path = bugreportZipPath ?: return false
            val zipFile = File(path)
            if (!zipFile.exists() || !zipFile.canRead()) return false

            return try {
                // Peek into the zip to check if it contains a btsnoop entry
                ZipFile(zipFile).use { zip ->
                    zip.entries().asSequence().any { entry ->
                        !entry.isDirectory &&
                            SNOOP_ENTRY_SUFFIXES.any { suffix ->
                                entry.name.endsWith(suffix)
                            }
                    }
                }
            } catch (e: Exception) {
                Timber.w(e, "Failed to inspect bugreport zip")
                false
            }
        }

        override fun readSnoopLog(): Result<InputStream> {
            val path =
                bugreportZipPath
                    ?: return Result.failure(
                        IllegalStateException("No bugreport zip path set. Call setBugreportZip() first."),
                    )

            val zipFile = File(path)
            if (!zipFile.exists()) {
                return Result.failure(FileNotFoundException("Bugreport zip not found: $path"))
            }

            return try {
                val zip = ZipFile(zipFile)
                val snoopEntry =
                    findSnoopEntry(zip)
                        ?: return Result.failure(
                            FileNotFoundException(
                                "No btsnoop_hci.log entry found in bugreport zip. " +
                                    "Ensure HCI snoop logging was enabled when the bugreport was generated.",
                            ),
                        )

                // Extract the entry to a temporary file (needed because ZipInputStream
                // doesn't support efficient seeking, and the caller may need random access)
                val tempFile = File.createTempFile("btsnoop_extracted_", ".log")
                tempFile.deleteOnExit()
                zip.getInputStream(snoopEntry).use { input ->
                    tempFile.outputStream().use { output ->
                        input.copyTo(output)
                    }
                }
                Timber.i("Extracted btsnoop_hci.log from bugreport (%d bytes)", tempFile.length())
                Result.success(BufferedInputStream(FileInputStream(tempFile)))
            } catch (e: Exception) {
                Timber.w(e, "Failed to extract snoop log from bugreport")
                Result.failure(e)
            }
        }

        /**
         * Find the btsnoop_hci.log entry inside the zip.
         *
         * Searches entries whose name ends with known suffix patterns.
         * Prefers the exact filename "btsnoop_hci.log" when multiple matches exist.
         */
        internal fun findSnoopEntry(zip: ZipFile): ZipEntry? {
            val entries =
                zip.entries().asSequence()
                    .filter { !it.isDirectory }
                    .filter { entry ->
                        SNOOP_ENTRY_SUFFIXES.any { suffix -> entry.name.endsWith(suffix) }
                    }
                    .toList()

            // Prefer exact match
            return entries.find { it.name.endsWith("btsnoop_hci.log") }
                ?: entries.firstOrNull()
        }

        companion object {
            /**
             * Known suffix patterns for btsnoop entries inside bugreport zips.
             * Covers different bugreport formats across Android versions.
             */
            private val SNOOP_ENTRY_SUFFIXES =
                listOf(
                    "btsnoop_hci.log",
                )
        }
    }
