/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.fuzzing

import com.btsec.testtool.domain.model.FuzzingCategory
import com.btsec.testtool.domain.model.FuzzingPattern
import com.btsec.testtool.domain.model.FuzzingSeverity

/**
 * Fuzzing patterns specific to HFP (Hands-Free Profile) AT command injection.
 *
 * These patterns test for:
 * - Format string vulnerabilities (CVE-2020-16142)
 * - Buffer overflows
 * - Command injection
 * - Boundary violations
 *
 * Based on known vulnerabilities in automotive Bluetooth stacks.
 */
object HfpFuzzingPatterns {
    /**
     * Format string patterns - CVE-2020-16142 (Mercedes NTG5)
     *
     * Tests for improper handling of format specifiers in AT commands.
     * Vulnerable systems may leak memory or crash when processing these.
     */
    val formatStringPatterns =
        listOf(
            FuzzingPattern(
                id = "HFP-FMT-001",
                name = "Format String - %x",
                category = FuzzingCategory.AT_INJECTION,
                severity = FuzzingSeverity.HIGH,
                description = "Hex format specifier - potential memory leak",
                payloads =
                    listOf(
                        "AT+BTRH=%x%x%x%x%x",
                        "AT+CLCC=%x%x%x%x%x",
                        "AT+CMGS=%x%x%x%x%x",
                        "AT+BLDN%x%x%x%x%x",
                    ),
                cveReferences = listOf("CVE-2020-16142"),
            ),
            FuzzingPattern(
                id = "HFP-FMT-002",
                name = "Format String - %s",
                category = FuzzingCategory.AT_INJECTION,
                severity = FuzzingSeverity.HIGH,
                description = "String format specifier - potential crash",
                payloads =
                    listOf(
                        "AT+BTRH=%s%s%s%s",
                        "AT+CLCC=%s%s%s%s",
                        "AT+CMGS=%s%s%s%s",
                    ),
                cveReferences = listOf("CVE-2020-16142"),
            ),
            FuzzingPattern(
                id = "HFP-FMT-003",
                name = "Format String - %n",
                category = FuzzingCategory.AT_INJECTION,
                severity = FuzzingSeverity.CRITICAL,
                description = "Write specifier - potential arbitrary write",
                payloads =
                    listOf(
                        "AT+BTRH=%n%n%n%n",
                        "AT+CLCC=%n%n%n%n",
                    ),
                cveReferences = listOf("CVE-2020-16142"),
            ),
            FuzzingPattern(
                id = "HFP-FMT-004",
                name = "Format String - Combined",
                category = FuzzingCategory.AT_INJECTION,
                severity = FuzzingSeverity.HIGH,
                description = "Mixed format specifiers",
                payloads =
                    listOf(
                        "AT+BTRH=%x%s%n%x",
                        "AT+CLCC=%s%x%n%s",
                        "AT+CMGS=%n%x%s%x%n",
                    ),
                cveReferences = listOf("CVE-2020-16142"),
            ),
        )

    /**
     * Buffer overflow patterns
     *
     * Tests for lack of input validation on AT command length and parameters.
     */
    val bufferOverflowPatterns =
        listOf(
            FuzzingPattern(
                id = "HFP-OVF-001",
                name = "Long AT Command",
                category = FuzzingCategory.BUFFER_OVERFLOW,
                severity = FuzzingSeverity.MEDIUM,
                description = "Overlong AT command string",
                payloads =
                    listOf(
                        "AT+" + "A".repeat(1000),
                        "AT+" + "A".repeat(5000),
                        "AT+CLCC=" + "A".repeat(1000),
                    ),
                cveReferences = listOf(),
            ),
            FuzzingPattern(
                id = "HFP-OVF-002",
                name = "Repeated Parameter",
                category = FuzzingCategory.BUFFER_OVERFLOW,
                severity = FuzzingSeverity.MEDIUM,
                description = "AT command with excessive repeated parameters",
                payloads =
                    listOf(
                        "AT+BTRH=" + "1,".repeat(100),
                        "AT+CLCC=" + "0,".repeat(200),
                    ),
                cveReferences = listOf(),
            ),
            FuzzingPattern(
                id = "HFP-OVF-003",
                name = "Nested Parameters",
                category = FuzzingCategory.BUFFER_OVERFLOW,
                severity = FuzzingSeverity.MEDIUM,
                description = "Deeply nested AT command parameters",
                payloads =
                    listOf(
                        "AT+CMGS=" + "(" + "A" + ",".repeat(50) + ")",
                        "AT+BLDN=" + "(".repeat(20) + ")".repeat(20),
                    ),
                cveReferences = listOf(),
            ),
        )

    /**
     * Command injection patterns
     *
     * Tests for improper separation of AT commands.
     */
    val commandInjectionPatterns =
        listOf(
            FuzzingPattern(
                id = "HFP-INJ-001",
                name = "Semicolon Separator",
                category = FuzzingCategory.COMMAND_INJECTION,
                severity = FuzzingSeverity.HIGH,
                description = "Multiple AT commands via semicolon",
                payloads =
                    listOf(
                        "AT+CLCC;ATD1234567890",
                        "AT+BTRH;AT+CLCC",
                        "AT+BLDN;AT+CMGS",
                    ),
                cveReferences = listOf(),
            ),
            FuzzingPattern(
                id = "HFP-INJ-002",
                name = "Shell Command Injection",
                category = FuzzingCategory.COMMAND_INJECTION,
                severity = FuzzingSeverity.CRITICAL,
                description = "Shell escape sequences",
                payloads =
                    listOf(
                        "AT+CLCC && shell",
                        "AT+BTRH | cmd",
                        "AT+BLDN; id",
                    ),
                cveReferences = listOf(),
            ),
            FuzzingPattern(
                id = "HFP-INJ-003",
                name = "Escape Sequence Injection",
                category = FuzzingCategory.COMMAND_INJECTION,
                severity = FuzzingSeverity.MEDIUM,
                description = "ANSI escape sequences",
                payloads =
                    listOf(
                        "AT+CLCC\u001b[2J",
                        "AT+BTRH\u001b[H",
                        "AT+BLDN\u001b[0m",
                    ),
                cveReferences = listOf(),
            ),
        )

    /**
     * Boundary violation patterns
     *
     * Tests for integer overflow and boundary conditions.
     */
    val boundaryViolationPatterns =
        listOf(
            FuzzingPattern(
                id = "HFP-BND-001",
                name = "Negative Integer",
                category = FuzzingCategory.INTEGER_OVERFLOW,
                severity = FuzzingSeverity.MEDIUM,
                description = "Negative values in numeric AT parameters",
                payloads =
                    listOf(
                        "AT+CLCC=-1",
                        "AT+BTRH=-99999",
                        "AT+CMGS=-2147483648",
                    ),
                cveReferences = listOf(),
            ),
            FuzzingPattern(
                id = "HFP-BND-002",
                name = "Integer Overflow",
                category = FuzzingCategory.INTEGER_OVERFLOW,
                severity = FuzzingSeverity.MEDIUM,
                description = "Maximum integer values",
                payloads =
                    listOf(
                        "AT+CLCC=2147483647",
                        "AT+BTRH=4294967295",
                        "AT+CMGS=999999999999999",
                    ),
                cveReferences = listOf(),
            ),
            FuzzingPattern(
                id = "HFP-BND-003",
                name = "Zero Value",
                category = FuzzingCategory.INTEGER_OVERFLOW,
                severity = FuzzingSeverity.LOW,
                description = "Zero and null boundary conditions",
                payloads =
                    listOf(
                        "AT+CLCC=0",
                        "AT+BTRH=00",
                        "AT+CMGS=",
                    ),
                cveReferences = listOf(),
            ),
        )

    /**
     * HFP-specific command patterns
     *
     * Tests for vulnerabilities in standard HFP AT commands.
     */
    val hfpCommandPatterns =
        listOf(
            FuzzingPattern(
                id = "HFP-CMD-001",
                name = "BLDN (Last Number Redial)",
                category = FuzzingCategory.HFP_COMMAND,
                severity = FuzzingSeverity.MEDIUM,
                description = "Test BLDN command with malformed input",
                payloads =
                    listOf(
                        "AT+BLDN",
                        "AT+BLDN=",
                        "AT+BLDN=%x%x%x",
                        "AT+BLDN;ATD0000",
                    ),
                cveReferences = listOf("CVE-2020-16142"),
            ),
            FuzzingPattern(
                id = "HFP-CMD-002",
                name = "CLCC (List Current Calls)",
                category = FuzzingCategory.HFP_COMMAND,
                severity = FuzzingSeverity.MEDIUM,
                description = "Test CLCC command for injection",
                payloads =
                    listOf(
                        "AT+CLCC",
                        "AT+CLCC=?",
                        "AT+CLCC=%s%s%s",
                    ),
                cveReferences = listOf(),
            ),
            FuzzingPattern(
                id = "HFP-CMD-003",
                name = "BRSF (Bluetooth Retrieve Supported Features)",
                category = FuzzingCategory.HFP_COMMAND,
                severity = FuzzingSeverity.MEDIUM,
                description = "Test BRSF with overflow values",
                payloads =
                    listOf(
                        "AT+BRSF=999999",
                        "AT+BRSF=%n",
                        "AT+BRSF=" + "9".repeat(100),
                    ),
                cveReferences = listOf(),
            ),
            FuzzingPattern(
                id = "HFP-CMD-004",
                name = "CIND (Indicator Update)",
                category = FuzzingCategory.HFP_COMMAND,
                severity = FuzzingSeverity.MEDIUM,
                description = "Test CIND indicator manipulation",
                payloads =
                    listOf(
                        "AT+CIND?",
                        "AT+CIND=%x",
                        "AT+CIND=" + "1,".repeat(50),
                    ),
                cveReferences = listOf(),
            ),
            FuzzingPattern(
                id = "HFP-CMD-005",
                name = "CMGS (Send Message)",
                category = FuzzingCategory.HFP_COMMAND,
                severity = FuzzingSeverity.HIGH,
                description = "Test CMGS for SMS injection",
                payloads =
                    listOf(
                        "AT+CMGS=" + "A".repeat(1000),
                        "AT+CMGS=%x%x%x",
                        "AT+CMGS;ATD0000",
                    ),
                cveReferences = listOf(),
            ),
        )

    /**
     * Get all HFP fuzzing patterns.
     */
    fun allPatterns(): List<FuzzingPattern> =
        listOf(
            formatStringPatterns,
            bufferOverflowPatterns,
            commandInjectionPatterns,
            boundaryViolationPatterns,
            hfpCommandPatterns,
        ).flatten()

    /**
     * Get patterns by category.
     */
    fun byCategory(category: FuzzingCategory): List<FuzzingPattern> = allPatterns().filter { it.category == category }

    /**
     * Get patterns by severity.
     */
    fun bySeverity(severity: FuzzingSeverity): List<FuzzingPattern> =
        allPatterns().filter { it.severity == severity }

    /**
     * Get patterns with CVE references.
     */
    fun withCveReferences(): List<FuzzingPattern> = allPatterns().filter { it.cveReferences.isNotEmpty() }
}
