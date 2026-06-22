/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.model

/**
 * File format for encrypted export operations.
 * Distinct from [com.btsec.testtool.domain.repository.ExportFormat] used for reports.
 */
enum class ExportFileFormat { JSON, CSV, PDF }

/**
 * Encryption algorithm for export operations.
 */
enum class EncryptionAlgorithm { AES_256, ZIP_PASSWORD }

/**
 * Configuration for encrypted export operations.
 *
 * @property format Output format (JSON, CSV, PDF).
 * @property encrypt Whether to encrypt the exported file.
 * @property password Optional password; if null and encrypt is true, one will be generated.
 * @property autoGeneratePassword Whether to auto-generate a password when none is provided.
 * @property algorithm Encryption algorithm to use.
 */
data class ExportConfig(
    val format: ExportFileFormat = ExportFileFormat.JSON,
    val encrypt: Boolean = true,
    val password: String? = null,
    val autoGeneratePassword: Boolean = true,
    val algorithm: EncryptionAlgorithm = EncryptionAlgorithm.AES_256,
)

/**
 * Result of an encrypted export operation.
 *
 * @property file The resulting (encrypted) file.
 * @property password The password used for encryption (null if not encrypted).
 * @property encrypted Whether the file was encrypted.
 * @property fileSizeBytes Size of the resulting file in bytes.
 */
data class ExportResult(
    val file: java.io.File,
    val password: String?,
    val encrypted: Boolean,
    val fileSizeBytes: Long,
)
