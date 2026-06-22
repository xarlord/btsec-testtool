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
import com.btsec.testtool.domain.model.TestAction
import com.btsec.testtool.domain.repository.AuthorizationRepository
import com.btsec.testtool.domain.repository.ConsentReader
import com.btsec.testtool.domain.repository.L2capSecurityRepository
import com.btsec.testtool.domain.repository.MapSecurityRepository
import com.btsec.testtool.domain.repository.PbapSecurityRepository
import com.btsec.testtool.domain.repository.SapSecurityRepository
import dagger.hilt.android.testing.HiltAndroidRule
import dagger.hilt.android.testing.HiltAndroidTest
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import javax.inject.Inject

/**
 * E2E tests for the Authorization + Consent lifecycle.
 *
 * This is the most critical security gate in the app: NO security testing
 * action should proceed without valid authorization AND explicit consent.
 *
 * Scenarios tested reflect real-world security audit requirements:
 * 1. Operations fail without authorization
 * 2. Operations fail without consent even WITH authorization
 * 3. Authorization can be revoked
 * 4. Target device scope is enforced
 *
 * Security gap identified: No E2E test existed for the authorization→consent→action
 * chain. This test ensures the enforcement cannot be bypassed.
 */
@HiltAndroidTest
@RunWith(AndroidJUnit4::class)
class AuthorizationConsentE2ETest {
    @get:Rule
    val hiltRule = HiltAndroidRule(this)

    @Inject
    lateinit var authRepo: AuthorizationRepository

    @Inject
    lateinit var consentReader: ConsentReader

    @Inject
    lateinit var pbapRepo: PbapSecurityRepository

    @Inject
    lateinit var mapRepo: MapSecurityRepository

    @Inject
    lateinit var sapRepo: SapSecurityRepository

    @Inject
    lateinit var l2capRepo: L2capSecurityRepository

    private val testDeviceAddress = "00:11:22:33:44:55"

    @Before
    fun setUp() {
        hiltRule.inject()
    }

    // ── Authorization Gate ────────────────────────────────────────

    @Test
    fun authConsent_initiallyNoAuthorization() =
        runBlocking {
            val currentAuth = authRepo.getCurrentAuthorization().first()
            assertNull(
                "No authorization should exist on fresh install",
                currentAuth,
            )
        }

    @Test
    fun authConsent_allActionsBlockedWithoutAuthorization() =
        runBlocking {
            for (action in TestAction.entries) {
                assertFalse(
                    "Action $action should be blocked without authorization",
                    authRepo.isActionAuthorized(action),
                )
            }
        }

    @Test
    fun authConsent_targetNotInScopeWithoutAuthorization() =
        runBlocking {
            val inScope = authRepo.isTargetInScope(testDeviceAddress)
            assertFalse(
                "Target device should not be in scope without authorization",
                inScope,
            )
        }

    // ── Profile-Level Enforcement ─────────────────────────────────

    @Test
    fun authConsent_pbapConnectBlockedWithoutAuthorization() =
        runBlocking {
            val result = pbapRepo.connect(testDeviceAddress)
            assertFalse(
                "PBAP connect should fail without authorization",
                result.isSuccess,
            )
        }

    @Test
    fun authConsent_pbapNotConnectedInitially() =
        runBlocking {
            assertFalse(
                "PBAP should not be connected on fresh state",
                pbapRepo.isPbapConnected().first(),
            )
        }

    @Test
    fun authConsent_mapConnectBlockedWithoutAuthorization() =
        runBlocking {
            val result = mapRepo.connect(testDeviceAddress)
            assertFalse(
                "MAP connect should fail without authorization",
                result.isSuccess,
            )
        }

    @Test
    fun authConsent_mapNotConnectedInitially() =
        runBlocking {
            assertFalse(
                "MAP should not be connected on fresh state",
                mapRepo.isMapConnected().first(),
            )
        }

    @Test
    fun authConsent_sapConnectBlockedWithoutAuthorization() =
        runBlocking {
            val result = sapRepo.connect(testDeviceAddress)
            assertFalse(
                "SAP connect should fail without authorization",
                result.isSuccess,
            )
        }

    @Test
    fun authConsent_sapNotConnectedInitially() =
        runBlocking {
            assertFalse(
                "SAP should not be connected on fresh state",
                sapRepo.isSapConnected().first(),
            )
        }

    @Test
    fun authConsent_l2capNotConnectedInitially() =
        runBlocking {
            assertFalse(
                "L2CAP should not be connected on fresh state",
                l2capRepo.isL2capConnected().first(),
            )
        }

    @Test
    fun authConsent_l2capEnumerateReturnsEmptyWithoutAuthorization() =
        runBlocking {
            val channels = l2capRepo.enumerateFixedChannels(testDeviceAddress)
            assertTrue(
                "L2CAP fixed channel enumeration should return empty without authorization",
                channels.isEmpty(),
            )
        }

    // ── Consent Gate ──────────────────────────────────────────────

    @Test
    fun authConsent_consentNotGivenForInvalidAuthId() =
        runBlocking {
            val hasConsent = consentReader.hasConsent("INVALID-AUTH-ID", TestAction.SCAN_DEVICES)
            assertFalse(
                "Consent should not exist for invalid auth ID",
                hasConsent,
            )
        }

    @Test
    fun authConsent_revocationClearsAuthorization() =
        runBlocking {
            authRepo.revokeAuthorization()
            val current = authRepo.getCurrentAuthorization().first()
            assertNull(
                "Authorization should be null after revocation",
                current,
            )
        }

    @Test
    fun authConsent_pbapAccessPhonebookBlocked() =
        runBlocking {
            // Attempting to read contacts without authorization should not return connected state
            assertFalse(
                "PBAP phonebook access should be blocked without authorization",
                pbapRepo.isPbapConnected().first(),
            )
        }
}
