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
 * Represents a single step in the onboarding tutorial flow.
 */
data class OnboardingStep(
    val id: String,
    val title: String,
    val description: String,
    val feature: OnboardingFeature,
    val icon: String,
    val order: Int
)

/**
 * Features covered by the onboarding tutorial.
 */
enum class OnboardingFeature {
    BLE_SCANNING,
    GATT_CONNECTION,
    SERVICE_DISCOVERY,
    VULNERABILITY_SCAN,
    FUZZING,
    REPORT_GENERATION,
    SETTINGS,
    BR_EDR_PROFILES
}

/**
 * Tracks the onboarding state for a user.
 * Persisted via DataStore so the tutorial only shows once.
 */
data class OnboardingState(
    val isCompleted: Boolean,
    val completedSteps: Set<String>,
    val currentStepIndex: Int,
    val skipped: Boolean,
    val completedAt: Long?,
    val totalSteps: Int
) {
    val progress: Float get() = if (totalSteps == 0) 0f else completedSteps.size.toFloat() / totalSteps
}

/**
 * Actions the user can take during onboarding.
 */
enum class OnboardingAction {
    NEXT, PREVIOUS, SKIP, COMPLETE, RESTART
}
