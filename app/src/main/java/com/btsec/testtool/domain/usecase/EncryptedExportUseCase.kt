/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.ExportResult
import net.lingala.zip4j.ZipFile
import net.lingala.zip4j.model.ZipParameters
import net.lingala.zip4j.model.enums.AesKeyStrength
import net.lingala.zip4j.model.enums.EncryptionMethod
import java.io.File
import java.security.SecureRandom
import javax.inject.Inject

/**
 * Use case for exporting data with password-protected ZIP encryption using AES-256.
 *
 * Provides methods to:
 * - Export raw byte data as an AES-256 encrypted ZIP file
 * - Auto-generate secure passwords
 * - Encrypt existing files into password-protected ZIPs
 *
 * Only to be used for AUTHORIZED security testing purposes.
 */
class EncryptedExportUseCase @Inject constructor() {

    companion object {
        private const val DEFAULT_PASSWORD_LENGTH = 16
        private const val ALPHANUMERIC_CHARSET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    }

    /**
     * Export data as a password-protected ZIP file.
     *
     * @param data The raw data to export.
     * @param filename The name for the file inside the ZIP (also determines ZIP name).
     * @param password The password to protect the ZIP with.
     * @param outputDir Directory where the ZIP file will be created.
     * @return [ExportResult] with details about the exported file.
     */
    fun exportWithPassword(
        data: ByteArray,
        filename: String,
        password: String,
        outputDir: File
    ): ExportResult {
        require(password.isNotEmpty()) { "Password must not be empty" }

        // Write data to a temporary file in a separate temp subdir to avoid name collisions
        val tempSubDir = File(outputDir, "tmp_export_${System.nanoTime()}")
        tempSubDir.mkdirs()
        val tempFile = File(tempSubDir, filename)
        tempFile.writeBytes(data)

        return try {
            val zipBaseName = File(filename).nameWithoutExtension
            val zipFileName = "$zipBaseName.zip"
            val zipFile = File(outputDir, zipFileName)

            if (zipFile.exists()) {
                zipFile.delete()
            }

            val zipParameters = ZipParameters().apply {
                isEncryptFiles = true
                encryptionMethod = EncryptionMethod.AES
                aesKeyStrength = AesKeyStrength.KEY_STRENGTH_256
                fileNameInZip = filename
            }

            ZipFile(zipFile, password.toCharArray()).use { zip ->
                zip.addFile(tempFile, zipParameters)
            }

            ExportResult(
                file = zipFile,
                password = password,
                encrypted = true,
                fileSizeBytes = zipFile.length()
            )
        } finally {
            tempFile.delete()
            tempSubDir.delete()
        }
    }

    /**
     * Export data with an auto-generated secure password.
     *
     * @param data The raw data to export.
     * @param filename The name for the file inside the ZIP.
     * @param outputDir Directory where the ZIP file will be created.
     * @return [ExportResult] with the generated password and file details.
     */
    fun exportWithAutoPassword(
        data: ByteArray,
        filename: String,
        outputDir: File
    ): ExportResult {
        val password = generateSecurePassword(DEFAULT_PASSWORD_LENGTH)
        return exportWithPassword(data, filename, password, outputDir)
    }

    /**
     * Generate a cryptographically secure random alphanumeric password.
     *
     * @param length The desired password length (default 16).
     * @return A securely generated alphanumeric password.
     */
    fun generateSecurePassword(length: Int = DEFAULT_PASSWORD_LENGTH): String {
        require(length > 0) { "Password length must be positive" }
        val random = SecureRandom()
        val charset = ALPHANUMERIC_CHARSET
        return (1..length)
            .map { charset[random.nextInt(charset.length)] }
            .joinToString("")
    }

    /**
     * Encrypt an existing file into a password-protected ZIP.
     *
     * @param sourceFile The file to encrypt.
     * @param password The password to protect the ZIP with.
     * @param outputDir Directory where the ZIP file will be created.
     * @return [ExportResult] with details about the encrypted ZIP file.
     */
    fun encryptFile(
        sourceFile: File,
        password: String,
        outputDir: File
    ): ExportResult {
        require(sourceFile.exists()) { "Source file does not exist: ${sourceFile.absolutePath}" }
        require(password.isNotEmpty()) { "Password must not be empty" }

        val zipFileName = sourceFile.nameWithoutExtension + ".zip"
        val zipFile = File(outputDir, zipFileName)

        // If a zip with the same name exists, delete it
        if (zipFile.exists()) {
            zipFile.delete()
        }

        val zipParameters = ZipParameters().apply {
            isEncryptFiles = true
            encryptionMethod = EncryptionMethod.AES
            aesKeyStrength = AesKeyStrength.KEY_STRENGTH_256
            fileNameInZip = sourceFile.name
        }

        ZipFile(zipFile, password.toCharArray()).use { zip ->
            zip.addFile(sourceFile, zipParameters)
        }

        return ExportResult(
            file = zipFile,
            password = password,
            encrypted = true,
            fileSizeBytes = zipFile.length()
        )
    }
}
