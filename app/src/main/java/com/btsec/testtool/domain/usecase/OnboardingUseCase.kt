/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.OnboardingAction
import com.btsec.testtool.domain.model.OnboardingFeature
import com.btsec.testtool.domain.model.OnboardingState
import com.btsec.testtool.domain.model.OnboardingStep
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Use case for managing the onboarding tutorial flow.
 *
 * Provides the ordered list of onboarding steps, handles
 * state transitions for next/previous/skip/complete/restart
 * actions, and tracks which steps the user has completed.
 */
@Singleton
class OnboardingUseCase @Inject constructor() {

    /**
     * Returns the 8-step onboarding tutorial sequence,
     * one step per [OnboardingFeature], ordered 1–8.
     */
    fun getOnboardingSteps(): List<OnboardingStep> = listOf(
        OnboardingStep(
            id = "step_ble_scanning",
            title = "BLE Scanning",
            description = "Discover nearby Bluetooth Low Energy devices and view their advertised services and signal strength.",
            feature = OnboardingFeature.BLE_SCANNING,
            icon = "bluetooth_searching",
            order = 1
        ),
        OnboardingStep(
            id = "step_gatt_connection",
            title = "GATT Connection",
            description = "Connect to BLE devices and interact with their GATT services and characteristics.",
            feature = OnboardingFeature.GATT_CONNECTION,
            icon = "cable",
            order = 2
        ),
        OnboardingStep(
            id = "step_service_discovery",
            title = "Service Discovery",
            description = "Enumerate all services, characteristics, and descriptors exposed by a connected device.",
            feature = OnboardingFeature.SERVICE_DISCOVERY,
            icon = "manage_search",
            order = 3
        ),
        OnboardingStep(
            id = "step_vulnerability_scan",
            title = "Vulnerability Scan",
            description = "Run automated security tests to identify known vulnerabilities and misconfigurations.",
            feature = OnboardingFeature.VULNERABILITY_SCAN,
            icon = "security",
            order = 4
        ),
        OnboardingStep(
            id = "step_fuzzing",
            title = "Fuzzing",
            description = "Send malformed and edge-case data to device services to uncover hidden flaws.",
            feature = OnboardingFeature.FUZZING,
            icon = "bug_report",
            order = 5
        ),
        OnboardingStep(
            id = "step_report_generation",
            title = "Report Generation",
            description = "Export detailed security assessment reports in multiple formats for documentation.",
            feature = OnboardingFeature.REPORT_GENERATION,
            icon = "summarize",
            order = 6
        ),
        OnboardingStep(
            id = "step_settings",
            title = "Settings",
            description = "Configure scanning preferences, default parameters, and application behavior.",
            feature = OnboardingFeature.SETTINGS,
            icon = "settings",
            order = 7
        ),
        OnboardingStep(
            id = "step_br_edr_profiles",
            title = "BR/EDR Profiles",
            description = "Test classic Bluetooth profiles including RFCOMM, SDP, and other legacy protocols.",
            feature = OnboardingFeature.BR_EDR_PROFILES,
            icon = "bluetooth",
            order = 8
        )
    )

    /**
     * Creates the initial onboarding state for a first-time user.
     */
    fun createInitialState(): OnboardingState = OnboardingState(
        isCompleted = false,
        completedSteps = emptySet(),
        currentStepIndex = 0,
        skipped = false,
        completedAt = null,
        totalSteps = getOnboardingSteps().size
    )

    /**
     * Handles a user action during onboarding and returns the new state.
     */
    fun handleAction(
        state: OnboardingState,
        action: OnboardingAction,
        totalSteps: Int
    ): OnboardingState = when (action) {
        OnboardingAction.NEXT -> {
            val steps = getOnboardingSteps()
            val currentStepId = steps.getOrNull(state.currentStepIndex)?.id ?: ""
            val newCompletedSteps = state.completedSteps + currentStepId
            val newIndex = if (state.currentStepIndex < totalSteps - 1) {
                state.currentStepIndex + 1
            } else {
                state.currentStepIndex
            }
            state.copy(
                currentStepIndex = newIndex,
                completedSteps = newCompletedSteps
            )
        }

        OnboardingAction.PREVIOUS -> {
            val newIndex = if (state.currentStepIndex > 0) {
                state.currentStepIndex - 1
            } else {
                state.currentStepIndex
            }
            state.copy(currentStepIndex = newIndex)
        }

        OnboardingAction.SKIP -> state.copy(
            isCompleted = true,
            skipped = true,
            completedAt = System.currentTimeMillis()
        )

        OnboardingAction.COMPLETE -> {
            val allStepIds = getOnboardingSteps().map { it.id }.toSet()
            state.copy(
                isCompleted = true,
                completedSteps = allStepIds,
                completedAt = System.currentTimeMillis()
            )
        }

        OnboardingAction.RESTART -> createInitialState()
    }

    /**
     * Returns whether the given step has been completed.
     */
    fun isStepCompleted(state: OnboardingState, stepId: String): Boolean =
        stepId in state.completedSteps

    /**
     * Returns the step at the given index, or null if out of bounds.
     */
    fun getStepByIndex(steps: List<OnboardingStep>, index: Int): OnboardingStep? =
        steps.getOrNull(index)

    /**
     * Returns whether the current index is the last step.
     */
    fun isLastStep(currentIndex: Int, totalSteps: Int): Boolean =
        currentIndex == totalSteps - 1

    /**
     * Returns whether the current index is the first step.
     */
    fun isFirstStep(currentIndex: Int): Boolean = currentIndex == 0
}
