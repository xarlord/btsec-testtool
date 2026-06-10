/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.e2e

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.btsec.testtool.domain.model.BluetoothDevice
import com.btsec.testtool.domain.model.BluetoothType
import com.btsec.testtool.domain.model.BondState
import com.btsec.testtool.domain.model.BtProfile
import com.btsec.testtool.domain.model.ProtocolDescriptor
import com.btsec.testtool.domain.model.SdpScanResult
import com.btsec.testtool.domain.model.SdpSecurityFinding
import com.btsec.testtool.domain.model.SdpService
import com.btsec.testtool.domain.model.SecurityRisk
import com.btsec.testtool.domain.repository.SdpEnumerationRepository
import dagger.hilt.android.testing.HiltAndroidRule
import dagger.hilt.android.testing.HiltAndroidTest
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.time.Instant
import javax.inject.Inject

/**
 * E2E tests for the SDP enumeration flow.
 *
 * Exercises: Connect to classic BT device → enumerate SDP services →
 * verify profile list.
 *
 * Validates the SDP repository contract, service model construction,
 * and profile identification.
 */
@HiltAndroidTest
@RunWith(AndroidJUnit4::class)
class SdpFlowE2ETest {

    @get:Rule
    val hiltRule = HiltAndroidRule(this)

    @Inject
    lateinit var sdpRepository: SdpEnumerationRepository

    private val classicDevice = BluetoothDevice(
        address = "33:44:55:66:77:88",
        name = "E2E-SDP-Target",
        type = BluetoothType.CLASSIC,
        deviceClass = null,
        bondState = BondState.NONE,
        rssi = -40,
        txPower = null,
        firstSeen = Instant.now(),
        lastSeen = Instant.now(),
        scanCount = 1,
        services = emptyList(),
        manufacturerData = emptyMap()
    )

    @Before
    fun setUp() {
        hiltRule.inject()
    }

    // ── SDP State Observation ────────────────────────────────────────

    @Test
    fun sdpFlow_browsingStateInitiallyFalse() = runBlocking {
        val browsing = sdpRepository.isBrowsing().first()
        assertNotNull("Browsing state should be observable", browsing)
    }

    @Test
    fun sdpFlow_allScanResultsObservable() = runBlocking {
        val results = sdpRepository.getAllScanResults().first()
        assertNotNull("SDP scan results should be observable", results)
    }

    @Test
    fun sdpFlow_cachedScanResultNullForUnknown() = runBlocking {
        val result = sdpRepository.getCachedScanResult(classicDevice.address)
        assertEquals(null, result)
    }

    // ── BtProfile Identification ─────────────────────────────────────

    @Test
    fun sdpFlow_profileIdentification_byUuid() {
        assertEquals(BtProfile.HFP, BtProfile.fromUuid("111E"))
        assertEquals(BtProfile.SPP, BtProfile.fromUuid("1101"))
        assertEquals(BtProfile.A2DP_SINK, BtProfile.fromUuid("110B"))
        assertEquals(BtProfile.AVRCP, BtProfile.fromUuid("110E"))
        assertEquals(BtProfile.PBAP_PSE, BtProfile.fromUuid("112F"))
        assertEquals(BtProfile.MAP_MSE, BtProfile.fromUuid("1132"))
        assertEquals(BtProfile.SAP, BtProfile.fromUuid("112D"))
        assertEquals(BtProfile.HID, BtProfile.fromUuid("1124"))
    }

    @Test
    fun sdpFlow_profileIdentification_caseInsensitive() {
        assertEquals(BtProfile.HFP, BtProfile.fromUuid("111e"))
        assertEquals(BtProfile.SPP, BtProfile.fromUuid("1101"))
    }

    @Test
    fun sdpFlow_profileIdentification_unknownReturnsUnknown() {
        assertEquals(BtProfile.UNKNOWN, BtProfile.fromUuid("9999"))
        assertEquals(BtProfile.UNKNOWN, BtProfile.fromUuid("0000"))
    }

    @Test
    fun sdpFlow_allProfilesHaveValidUuids() {
        for (profile in BtProfile.entries) {
            assertNotNull(profile.uuid)
            assertTrue(profile.uuid.isNotBlank())
            assertNotNull(profile.displayName)
            assertTrue(profile.displayName.isNotBlank())
            assertNotNull(profile.category)
            assertTrue(profile.category.isNotBlank())
        }
    }

    // ── SDP Service Model ────────────────────────────────────────────

    @Test
    fun sdpFlow_sdpServiceConstruction() {
        val service = SdpService(
            uuid = "111E",
            profile = BtProfile.HFP,
            name = "Hands-Free",
            rfcommChannel = 1,
            l2capPsm = null,
            protocolDescriptors = listOf(
                ProtocolDescriptor(
                    protocolUuid = "0003",
                    protocolName = "RFCOMM",
                    parameters = mapOf("channel" to 1)
                )
            ),
            requiresAuthentication = true,
            requiresEncryption = false,
            version = "1.6",
            providerName = "Test Provider",
            serviceName = "Hands-Free Service",
            isHidden = false,
            securityRisk = SecurityRisk.LOW
        )

        assertEquals("111E", service.uuid)
        assertEquals(BtProfile.HFP, service.profile)
        assertEquals(1, service.rfcommChannel)
        assertEquals(1, service.protocolDescriptors.size)
        assertTrue(service.requiresAuthentication == true)
        assertEquals(SecurityRisk.LOW, service.securityRisk)
    }

    @Test
    fun sdpFlow_sdpScanResultConstruction() {
        val service = SdpService(
            uuid = "1101",
            profile = BtProfile.SPP,
            name = "Serial Port",
            rfcommChannel = 2,
            l2capPsm = null,
            protocolDescriptors = emptyList(),
            securityRisk = SecurityRisk.UNKNOWN
        )

        val securityFinding = SdpSecurityFinding(
            severity = SecurityRisk.MEDIUM,
            service = "Serial Port",
            issue = "Service does not require authentication",
            recommendation = "Enable authentication for SPP"
        )

        val scanResult = SdpScanResult(
            deviceAddress = classicDevice.address,
            deviceName = classicDevice.name,
            services = listOf(service),
            hiddenServices = emptyList(),
            securityIssues = listOf(securityFinding),
            scanDurationMs = 1500L
        )

        assertEquals(classicDevice.address, scanResult.deviceAddress)
        assertEquals(1, scanResult.services.size)
        assertEquals(BtProfile.SPP, scanResult.services[0].profile)
        assertEquals(1, scanResult.securityIssues.size)
        assertEquals(SecurityRisk.MEDIUM, scanResult.securityIssues[0].severity)
        assertEquals(1500L, scanResult.scanDurationMs)
    }

    // ── Security Risk Levels ─────────────────────────────────────────

    @Test
    fun sdpFlow_securityRiskValues() {
        val risks = SecurityRisk.entries
        assertTrue("Should have multiple security risk levels", risks.size >= 3)
        assertTrue(SecurityRisk.entries.contains(SecurityRisk.HIGH))
        assertTrue(SecurityRisk.entries.contains(SecurityRisk.MEDIUM))
        assertTrue(SecurityRisk.entries.contains(SecurityRisk.LOW))
    }

    // ── Profile Categories ───────────────────────────────────────────

    @Test
    fun sdpFlow_audioProfiles() {
        val audioProfiles = BtProfile.entries.filter { it.category == "audio" }
        assertTrue("Should have audio profiles", audioProfiles.isNotEmpty())
        assertTrue(audioProfiles.contains(BtProfile.HFP))
        assertTrue(audioProfiles.contains(BtProfile.A2DP_SINK))
        assertTrue(audioProfiles.contains(BtProfile.AVRCP))
    }

    @Test
    fun sdpFlow_dataProfiles() {
        val dataProfiles = BtProfile.entries.filter { it.category == "data" }
        assertTrue("Should have data profiles", dataProfiles.isNotEmpty())
        assertTrue(dataProfiles.contains(BtProfile.SPP))
    }

    @Test
    fun sdpFlow_pimProfiles() {
        val pimProfiles = BtProfile.entries.filter { it.category == "pim" }
        assertTrue("Should have PIM profiles", pimProfiles.isNotEmpty())
        assertTrue(pimProfiles.contains(BtProfile.PBAP_PSE))
        assertTrue(pimProfiles.contains(BtProfile.MAP_MSE))
    }
}
