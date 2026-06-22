/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.common

import android.content.Context
import java.io.File

/**
 * Shared utility for validating file paths against path traversal attacks.
 *
 * Ensures that output paths are confined to allowed directories
 * (app internal storage, cache, and temp directories).
 */
object PathValidator {
    /**
     * Validate that the output path is within allowed directories.
     * Prevents path traversal attacks (e.g., `../../etc/passwd`).
     *
     * @param context Application context for resolving app-specific directories
     * @param outputPath The file path to validate
     * @return Result.success(File) if path is safe, Result.failure if traversal detected
     */
    fun getSafeFile(
        context: Context,
        outputPath: String,
    ): Result<File> {
        val file = File(outputPath)
        return try {
            val canonicalPath = file.canonicalPath
            val allowedDirs =
                listOfNotNull(
                    context.filesDir,
                    context.cacheDir,
                    context.getExternalFilesDir(null),
                    File(System.getProperty("java.io.tmpdir")),
                    File("/tmp"),
                ).map { it.canonicalPath }

            val isSafe =
                allowedDirs.any { base ->
                    canonicalPath.startsWith(base + File.separator) || canonicalPath == base
                }

            if (isSafe) {
                Result.success(file)
            } else {
                Result.failure(SecurityException("Invalid output path: Path traversal detected or path outside allowed directories"))
            }
        } catch (e: Exception) {
            Result.failure(SecurityException("Invalid output path", e))
        }
    }
}
