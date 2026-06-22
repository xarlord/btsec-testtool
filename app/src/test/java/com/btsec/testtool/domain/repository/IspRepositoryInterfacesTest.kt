/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.repository

import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests that verify the Interface Segregation Principle (ISP) refactoring.
 *
 * Each composite repository interface is checked to ensure it extends the
 * correct Reader and Writer sub-interfaces, confirming backward compatibility
 * while allowing clients to depend on narrower contracts.
 *
 * Related issues: #132, #178
 */
class IspRepositoryInterfacesTest {
    // ========== KeyExtractionRepository ==========

    @Test
    fun keyExtractionRepository_extendsKeyExtractionReader() {
        assertTrue(
            "KeyExtractionRepository should extend KeyExtractionReader",
            KeyExtractionReader::class.java.isAssignableFrom(KeyExtractionRepository::class.java),
        )
    }

    @Test
    fun keyExtractionRepository_extendsKeyExtractionWriter() {
        assertTrue(
            "KeyExtractionRepository should extend KeyExtractionWriter",
            KeyExtractionWriter::class.java.isAssignableFrom(KeyExtractionRepository::class.java),
        )
    }

    // ========== BluetoothRepository ==========

    @Test
    fun bluetoothRepository_extendsBluetoothStateReader() {
        assertTrue(
            "BluetoothRepository should extend BluetoothStateReader",
            BluetoothStateReader::class.java.isAssignableFrom(BluetoothRepository::class.java),
        )
    }

    @Test
    fun bluetoothRepository_extendsBluetoothOperationsWriter() {
        assertTrue(
            "BluetoothRepository should extend BluetoothOperationsWriter",
            BluetoothOperationsWriter::class.java.isAssignableFrom(BluetoothRepository::class.java),
        )
    }

    // ========== ReportRepository ==========

    @Test
    fun reportRepository_extendsReportReader() {
        assertTrue(
            "ReportRepository should extend ReportReader",
            ReportReader::class.java.isAssignableFrom(ReportRepository::class.java),
        )
    }

    @Test
    fun reportRepository_extendsReportWriter() {
        assertTrue(
            "ReportRepository should extend ReportWriter",
            ReportWriter::class.java.isAssignableFrom(ReportRepository::class.java),
        )
    }

    // ========== ConsentRepository ==========

    @Test
    fun consentRepository_extendsConsentReader() {
        assertTrue(
            "ConsentRepository should extend ConsentReader",
            ConsentReader::class.java.isAssignableFrom(ConsentRepository::class.java),
        )
    }

    @Test
    fun consentRepository_extendsConsentWriter() {
        assertTrue(
            "ConsentRepository should extend ConsentWriter",
            ConsentWriter::class.java.isAssignableFrom(ConsentRepository::class.java),
        )
    }

    // ========== VulnerabilityRepository ==========

    @Test
    fun vulnerabilityRepository_extendsVulnerabilityReader() {
        assertTrue(
            "VulnerabilityRepository should extend VulnerabilityReader",
            VulnerabilityReader::class.java.isAssignableFrom(VulnerabilityRepository::class.java),
        )
    }

    @Test
    fun vulnerabilityRepository_extendsVulnerabilityWriter() {
        assertTrue(
            "VulnerabilityRepository should extend VulnerabilityWriter",
            VulnerabilityWriter::class.java.isAssignableFrom(VulnerabilityRepository::class.java),
        )
    }

    // ========== FuzzingRepository ==========

    @Test
    fun fuzzingRepository_extendsFuzzingReader() {
        assertTrue(
            "FuzzingRepository should extend FuzzingReader",
            FuzzingReader::class.java.isAssignableFrom(FuzzingRepository::class.java),
        )
    }

    @Test
    fun fuzzingRepository_extendsFuzzingWriter() {
        assertTrue(
            "FuzzingRepository should extend FuzzingWriter",
            FuzzingWriter::class.java.isAssignableFrom(FuzzingRepository::class.java),
        )
    }

    // ========== BR/EDR Repository Interfaces (#331) ==========

    @Test
    fun sdpEnumerationRepository_exists() {
        assertTrue(
            "SdpEnumerationRepository should be an interface",
            SdpEnumerationRepository::class.java.isInterface,
        )
    }

    @Test
    fun rfcommFuzzingRepository_exists() {
        assertTrue(
            "RfcommFuzzingRepository should be an interface",
            RfcommFuzzingRepository::class.java.isInterface,
        )
    }

    @Test
    fun hfpSecurityRepository_exists() {
        assertTrue(
            "HfpSecurityRepository should be an interface",
            HfpSecurityRepository::class.java.isInterface,
        )
    }

    @Test
    fun avrcpSecurityRepository_exists() {
        assertTrue(
            "AvrcpSecurityRepository should be an interface",
            AvrcpSecurityRepository::class.java.isInterface,
        )
    }

    @Test
    fun pbapSecurityRepository_exists() {
        assertTrue(
            "PbapSecurityRepository should be an interface",
            PbapSecurityRepository::class.java.isInterface,
        )
    }

    @Test
    fun mapSecurityRepository_exists() {
        assertTrue(
            "MapSecurityRepository should be an interface",
            MapSecurityRepository::class.java.isInterface,
        )
    }

    @Test
    fun sapSecurityRepository_exists() {
        assertTrue(
            "SapSecurityRepository should be an interface",
            SapSecurityRepository::class.java.isInterface,
        )
    }

    @Test
    fun l2capSecurityRepository_exists() {
        assertTrue(
            "L2capSecurityRepository should be an interface",
            L2capSecurityRepository::class.java.isInterface,
        )
    }

    @Test
    fun snoopCaptureRepository_exists() {
        assertTrue(
            "SnoopCaptureRepository should be an interface",
            SnoopCaptureRepository::class.java.isInterface,
        )
    }
}
