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
import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

@DisplayName("OnboardingUseCase")
class OnboardingUseCaseTest {

    private lateinit var useCase: OnboardingUseCase

    @BeforeEach
    fun setUp() {
        useCase = OnboardingUseCase()
    }

    @Nested
    @DisplayName("getOnboardingSteps")
    inner class GetOnboardingSteps {

        @Test
        @DisplayName("should return 8 steps")
        fun testGetOnboardingSteps_has8Steps() {
            val steps = useCase.getOnboardingSteps()
            assertThat(steps).hasSize(8)
        }

        @Test
        @DisplayName("should cover all OnboardingFeature values")
        fun testGetOnboardingSteps_allFeaturesCovered() {
            val steps = useCase.getOnboardingSteps()
            val stepFeatures = steps.map { it.feature }.toSet()
            assertThat(stepFeatures).containsExactlyElementsIn(OnboardingFeature.entries)
        }

        @Test
        @DisplayName("steps should be ordered sequentially 1 through 8")
        fun testGetOnboardingSteps_orderedSequentially() {
            val steps = useCase.getOnboardingSteps()
            for (i in steps.indices) {
                assertThat(steps[i].order).isEqualTo(i + 1)
            }
        }
    }

    @Nested
    @DisplayName("createInitialState")
    inner class CreateInitialState {

        @Test
        @DisplayName("initial state should not be completed")
        fun testCreateInitialState_notCompleted() {
            val state = useCase.createInitialState()
            assertThat(state.isCompleted).isFalse()
            assertThat(state.completedSteps).isEmpty()
            assertThat(state.currentStepIndex).isEqualTo(0)
            assertThat(state.skipped).isFalse()
            assertThat(state.completedAt).isNull()
            assertThat(state.totalSteps).isEqualTo(8)
        }
    }

    @Nested
    @DisplayName("handleAction")
    inner class HandleAction {

        @Test
        @DisplayName("NEXT should advance currentStepIndex and mark step completed")
        fun testHandleAction_next_advances() {
            val initial = useCase.createInitialState()
            val next = useCase.handleAction(initial, OnboardingAction.NEXT, 8)
            assertThat(next.currentStepIndex).isEqualTo(1)
            assertThat(next.completedSteps).contains("step_ble_scanning")
        }

        @Test
        @DisplayName("PREVIOUS should go back one step")
        fun testHandleAction_previous_goesBack() {
            val initial = useCase.createInitialState()
            val next = useCase.handleAction(initial, OnboardingAction.NEXT, 8)
            val prev = useCase.handleAction(next, OnboardingAction.PREVIOUS, 8)
            assertThat(prev.currentStepIndex).isEqualTo(0)
        }

        @Test
        @DisplayName("SKIP should mark onboarding as completed and skipped")
        fun testHandleAction_skip_completes() {
            val initial = useCase.createInitialState()
            val skipped = useCase.handleAction(initial, OnboardingAction.SKIP, 8)
            assertThat(skipped.isCompleted).isTrue()
            assertThat(skipped.skipped).isTrue()
            assertThat(skipped.completedAt).isNotNull()
        }

        @Test
        @DisplayName("COMPLETE should mark all steps completed")
        fun testHandleAction_complete_allDone() {
            val initial = useCase.createInitialState()
            val completed = useCase.handleAction(initial, OnboardingAction.COMPLETE, 8)
            assertThat(completed.isCompleted).isTrue()
            assertThat(completed.completedSteps).hasSize(8)
            assertThat(completed.completedAt).isNotNull()
        }

        @Test
        @DisplayName("RESTART should reset to initial state")
        fun testHandleAction_restart_resets() {
            val initial = useCase.createInitialState()
            val completed = useCase.handleAction(initial, OnboardingAction.COMPLETE, 8)
            val restarted = useCase.handleAction(completed, OnboardingAction.RESTART, 8)
            assertThat(restarted.isCompleted).isFalse()
            assertThat(restarted.completedSteps).isEmpty()
            assertThat(restarted.currentStepIndex).isEqualTo(0)
            assertThat(restarted.skipped).isFalse()
        }

        @Test
        @DisplayName("NEXT at end should stay at end")
        fun testHandleAction_next_atEnd_staysAtEnd() {
            var state = useCase.createInitialState()
            // Advance to the last step
            repeat(7) {
                state = useCase.handleAction(state, OnboardingAction.NEXT, 8)
            }
            assertThat(state.currentStepIndex).isEqualTo(7)
            // Try to go past the end
            val atEnd = useCase.handleAction(state, OnboardingAction.NEXT, 8)
            assertThat(atEnd.currentStepIndex).isEqualTo(7)
        }

        @Test
        @DisplayName("PREVIOUS at start should stay at start")
        fun testHandleAction_previous_atStart_staysAtStart() {
            val initial = useCase.createInitialState()
            val stillAtStart = useCase.handleAction(initial, OnboardingAction.PREVIOUS, 8)
            assertThat(stillAtStart.currentStepIndex).isEqualTo(0)
        }
    }

    @Nested
    @DisplayName("isStepCompleted")
    inner class IsStepCompleted {

        @Test
        @DisplayName("should return true for a completed step")
        fun testIsStepCompleted_true() {
            val initial = useCase.createInitialState()
            val next = useCase.handleAction(initial, OnboardingAction.NEXT, 8)
            assertThat(useCase.isStepCompleted(next, "step_ble_scanning")).isTrue()
        }

        @Test
        @DisplayName("should return false for an incomplete step")
        fun testIsStepCompleted_false() {
            val initial = useCase.createInitialState()
            assertThat(useCase.isStepCompleted(initial, "step_ble_scanning")).isFalse()
        }
    }

    @Nested
    @DisplayName("isLastStep")
    inner class IsLastStep {

        @Test
        @DisplayName("should return true when at last step")
        fun testIsLastStep_true() {
            assertThat(useCase.isLastStep(7, 8)).isTrue()
        }

        @Test
        @DisplayName("should return false when not at last step")
        fun testIsLastStep_false() {
            assertThat(useCase.isLastStep(0, 8)).isFalse()
        }
    }

    @Nested
    @DisplayName("isFirstStep")
    inner class IsFirstStep {

        @Test
        @DisplayName("should return true when at first step")
        fun testIsFirstStep_true() {
            assertThat(useCase.isFirstStep(0)).isTrue()
        }

        @Test
        @DisplayName("should return false when not at first step")
        fun testIsFirstStep_false() {
            assertThat(useCase.isFirstStep(3)).isFalse()
        }
    }

    @Nested
    @DisplayName("getStepByIndex")
    inner class GetStepByIndex {

        @Test
        @DisplayName("should return step for valid index")
        fun testGetStepByIndex_valid() {
            val steps = useCase.getOnboardingSteps()
            val step = useCase.getStepByIndex(steps, 0)
            assertThat(step).isNotNull()
            assertThat(step!!.id).isEqualTo("step_ble_scanning")
        }

        @Test
        @DisplayName("should return null for out-of-bounds index")
        fun testGetStepByIndex_outOfBounds() {
            val steps = useCase.getOnboardingSteps()
            assertThat(useCase.getStepByIndex(steps, 99)).isNull()
        }
    }
}
