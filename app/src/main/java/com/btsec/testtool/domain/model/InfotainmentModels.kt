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
 * Vehicle vendor enumeration for infotainment system identification.
 */
enum class VehicleVendor(val displayName: String) {
    BMW("BMW"),
    MERCEDES_BENZ("Mercedes-Benz"),
    VW_GROUP("VW Group (VW/Audi/Skoda/SEAT)"),
    TESLA("Tesla"),
    BOSCH_ALPS("Bosch/Alps Alpine"),
    GENERIC("Generic"),
    UNKNOWN("Unknown"),
}

/**
 * Known infotainment unit types mapped to their vendors.
 */
enum class InfotainmentUnit(val vendor: VehicleVendor, val displayName: String) {
    BMW_HU_NBT(VehicleVendor.BMW, "HU_NBT (BMW i/X/3/5/7 Series 2010-2018)"),
    MB_NTG5(VehicleVendor.MERCEDES_BENZ, "NTG5 (Mercedes C-Class)"),
    VW_MIB3(VehicleVendor.VW_GROUP, "MIB3 (VW/Audi/Skoda/SEAT)"),
    TESLA_MCUMCU2(VehicleVendor.TESLA, "MCU/MCU2 (Tesla Model S/3/X/Y)"),
    BOSCH_MIB(VehicleVendor.BOSCH_ALPS, "Bosch/Alps Alpine Infotainment ECU"),
    GENERIC_UNIT(VehicleVendor.GENERIC, "Generic Infotainment"),
}

/**
 * Represents a known CVE affecting infotainment systems via Bluetooth.
 */
data class InfotainmentCve(
    val cveId: String,
    val name: String,
    val description: String,
    val affectedUnits: List<InfotainmentUnit>,
    val affectedProfiles: List<String>,
    val cvssScore: Double,
    val testMethod: String,
    val reference: String,
)

/**
 * Result of testing a single CVE against a target device.
 */
data class CveTestResult(
    val cve: InfotainmentCve,
    val tested: Boolean,
    val vulnerable: Boolean,
    val confidence: Double,
    val evidence: String,
    val testDurationMs: Long,
)

/**
 * Full test report for all infotainment CVEs tested against a device.
 */
data class InfotainmentTestReport(
    val targetDevice: String,
    val detectedUnit: InfotainmentUnit?,
    val results: List<CveTestResult>,
    val vulnerabilitiesFound: Int,
    val criticalCount: Int,
    val highCount: Int,
    val mediumCount: Int,
    val testedCveCount: Int,
    val testDurationMs: Long,
)
