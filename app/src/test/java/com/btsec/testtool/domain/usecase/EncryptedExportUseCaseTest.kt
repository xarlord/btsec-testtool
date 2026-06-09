/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.google.common.truth.Truth.assertThat
import net.lingala.zip4j.ZipFile
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File

/**
 * Unit tests for [EncryptedExportUseCase].
 *
 * Verifies password generation, encrypted ZIP creation, and content integrity.
 * Only for AUTHORIZED security testing purposes.
 */
class EncryptedExportUseCaseTest {

    private val useCase = EncryptedExportUseCase()

    @TempDir
    lateinit var tempDir: File

    // ── Password generation tests ──

    @Test
    @DisplayName("generateSecurePassword returns 16-char password by default")
    fun testGeneratePassword_defaultLength() {
        val password = useCase.generateSecurePassword()
        assertThat(password).hasLength(16)
    }

    @Test
    @DisplayName("generateSecurePassword returns custom-length password")
    fun testGeneratePassword_customLength() {
        val password = useCase.generateSecurePassword(24)
        assertThat(password).hasLength(24)
    }

    @Test
    @DisplayName("generateSecurePassword contains only alphanumeric characters")
    fun testGeneratePassword_containsAlphanumeric() {
        val password = useCase.generateSecurePassword(100)
        assertThat(password.matches(Regex("^[A-Za-z0-9]+$"))).isTrue()
    }

    @Test
    @DisplayName("generateSecurePassword produces unique passwords across calls")
    fun testGeneratePassword_uniqueAcrossCalls() {
        val passwords = (1..10).map { useCase.generateSecurePassword() }.toSet()
        // With 16-char alphanumeric passwords, all 10 should be unique
        assertThat(passwords).hasSize(10)
    }

    // ── exportWithPassword tests ──

    @Test
    @DisplayName("exportWithPassword creates an encrypted ZIP file")
    fun testExportWithPassword_createsEncryptedFile() {
        val data = "test data for encryption".toByteArray()
        val result = useCase.exportWithPassword(data, "test.txt", "secret123", tempDir)

        assertThat(result.file.exists()).isTrue()
        assertThat(result.file.name).isEqualTo("test.zip")
    }

    @Test
    @DisplayName("exportWithPassword produces a non-empty file")
    fun testExportWithPassword_fileNotEmpty() {
        val data = "test data for encryption".toByteArray()
        val result = useCase.exportWithPassword(data, "test.txt", "secret123", tempDir)

        assertThat(result.fileSizeBytes).isGreaterThan(0L)
    }

    @Test
    @DisplayName("exportWithPassword returns encrypted=true with the password used")
    fun testExportWithPassword_resultIsEncrypted() {
        val data = "test data for encryption".toByteArray()
        val result = useCase.exportWithPassword(data, "test.txt", "secret123", tempDir)

        assertThat(result.encrypted).isTrue()
        assertThat(result.password).isEqualTo("secret123")
    }

    // ── exportWithAutoPassword tests ──

    @Test
    @DisplayName("exportWithAutoPassword generates a password")
    fun testExportWithAutoPassword_generatesPassword() {
        val data = "auto password test".toByteArray()
        val result = useCase.exportWithAutoPassword(data, "auto.txt", tempDir)

        assertThat(result.password).isNotNull()
        assertThat(result.password).isNotEmpty()
    }

    @Test
    @DisplayName("exportWithAutoPassword creates an encrypted file")
    fun testExportWithAutoPassword_createsFile() {
        val data = "auto password test".toByteArray()
        val result = useCase.exportWithAutoPassword(data, "auto.txt", tempDir)

        assertThat(result.file.exists()).isTrue()
        assertThat(result.encrypted).isTrue()
    }

    @Test
    @DisplayName("exportWithAutoPassword generates a 16-char password")
    fun testExportWithAutoPassword_passwordLength16() {
        val data = "auto password test".toByteArray()
        val result = useCase.exportWithAutoPassword(data, "auto.txt", tempDir)

        assertThat(result.password).hasLength(16)
    }

    // ── encryptFile tests ──

    @Test
    @DisplayName("encryptFile creates an encrypted copy of an existing file")
    fun testEncryptFile_createsEncryptedCopy() {
        val sourceFile = File(tempDir, "source.txt")
        sourceFile.writeText("content to encrypt")

        val result = useCase.encryptFile(sourceFile, "mypassword", tempDir)

        assertThat(result.file.exists()).isTrue()
        assertThat(result.file.name).isEqualTo("source.zip")
        assertThat(result.encrypted).isTrue()
        assertThat(result.password).isEqualTo("mypassword")
    }

    @Test
    @DisplayName("encryptFile preserves content — can decrypt and verify original data")
    fun testEncryptFile_preservesContent() {
        val originalContent = "This is important AUTHORED test data!@#"
        val sourceFile = File(tempDir, "verify.txt")
        sourceFile.writeText(originalContent)

        val result = useCase.encryptFile(sourceFile, "testpass456", tempDir)

        // Decrypt using zip4j and verify content
        val extractDir = File(tempDir, "extracted")
        extractDir.mkdirs()

        ZipFile(result.file, "testpass456".toCharArray()).use { zip ->
            zip.extractAll(extractDir.absolutePath)
        }

        val extractedFile = File(extractDir, "verify.txt")
        assertThat(extractedFile.readText()).isEqualTo(originalContent)
    }
}
