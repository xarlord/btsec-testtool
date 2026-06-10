/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.DeviceScanState
import com.btsec.testtool.domain.model.ParallelScanConfig
import com.btsec.testtool.domain.model.ParallelScanResult
import com.btsec.testtool.domain.model.ParallelScanSession
import com.btsec.testtool.domain.model.ParallelScanTarget
import com.btsec.testtool.domain.model.ScanPriority
import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

@DisplayName("MultiDeviceScanUseCase")
class MultiDeviceScanUseCaseTest {

    private lateinit var useCase: MultiDeviceScanUseCase

    @BeforeEach
    fun setUp() {
        useCase = MultiDeviceScanUseCase()
    }

    private fun createTarget(
        address: String = "AA:BB:CC:DD:EE:FF",
        name: String? = "TestDevice",
        priority: ScanPriority = ScanPriority.NORMAL,
        state: DeviceScanState = DeviceScanState.QUEUED,
        slot: Int = -1
    ): ParallelScanTarget = ParallelScanTarget(
        deviceAddress = address,
        deviceName = name,
        priority = priority,
        state = state,
        assignedSlot = slot
    )

    private val defaultConfig = ParallelScanConfig(
        maxConcurrentConnections = 4,
        stopOnFirstCritical = false
    )

    @Nested
    @DisplayName("createSession")
    inner class CreateSession {

        @Test
        @DisplayName("assigns slots to targets up to max connections")
        fun testCreateSession_assignsSlots() {
            val targets = (0..5).map { i ->
                createTarget(address = "AA:BB:CC:DD:EE:0$i")
            }
            val session = useCase.createSession(targets, defaultConfig)

            assertThat(session.id).isNotEmpty()
            assertThat(session.targets).hasSize(6)
            // First 4 should have slots 0-3 assigned
            assertThat(session.targets[0].assignedSlot).isEqualTo(0)
            assertThat(session.targets[1].assignedSlot).isEqualTo(1)
            assertThat(session.targets[2].assignedSlot).isEqualTo(2)
            assertThat(session.targets[3].assignedSlot).isEqualTo(3)
            // Remaining 2 should have slot -1
            assertThat(session.targets[4].assignedSlot).isEqualTo(-1)
            assertThat(session.targets[5].assignedSlot).isEqualTo(-1)
        }

        @Test
        @DisplayName("creates session with empty targets")
        fun testCreateSession_emptyTargets() {
            val session = useCase.createSession(emptyList(), defaultConfig)

            assertThat(session.targets).isEmpty()
            assertThat(session.activeSlots).isEmpty()
            assertThat(session.results).isEmpty()
        }
    }

    @Nested
    @DisplayName("assignSlots")
    inner class AssignSlots {

        @Test
        @DisplayName("assigns slots to max 4 devices, rest remain QUEUED")
        fun testAssignSlots_max4Devices() {
            val targets = (0..6).map { i ->
                createTarget(address = "AA:BB:CC:DD:EE:0$i")
            }
            val assigned = useCase.assignSlots(targets, 4)

            assertThat(assigned).hasSize(7)
            assertThat(assigned.take(4).map { it.assignedSlot })
                .containsExactly(0, 1, 2, 3).inOrder()
            assertThat(assigned.drop(4).map { it.assignedSlot })
                .containsExactly(-1, -1, -1).inOrder()
        }

        @Test
        @DisplayName("respects priority ordering when sorted first")
        fun testAssignSlots_respectsPriority() {
            val targets = listOf(
                createTarget(address = "LOW_1", priority = ScanPriority.LOW),
                createTarget(address = "CRIT_1", priority = ScanPriority.CRITICAL),
                createTarget(address = "NORM_1", priority = ScanPriority.NORMAL),
                createTarget(address = "HIGH_1", priority = ScanPriority.HIGH),
                createTarget(address = "CRIT_2", priority = ScanPriority.CRITICAL)
            )

            val sorted = useCase.sortTargetsByPriority(targets)
            val assigned = useCase.assignSlots(sorted, 4)

            // First 4 should be the 2 CRITICAL, then HIGH, then NORMAL
            assertThat(assigned[0].priority).isEqualTo(ScanPriority.CRITICAL)
            assertThat(assigned[1].priority).isEqualTo(ScanPriority.CRITICAL)
            assertThat(assigned[2].priority).isEqualTo(ScanPriority.HIGH)
            assertThat(assigned[3].priority).isEqualTo(ScanPriority.NORMAL)
            // LOW should be the unassigned one
            assertThat(assigned[4].priority).isEqualTo(ScanPriority.LOW)
            assertThat(assigned[4].assignedSlot).isEqualTo(-1)
        }
    }

    @Nested
    @DisplayName("getNextTarget")
    inner class GetNextTarget {

        @Test
        @DisplayName("returns next queued device and assigns to freed slot")
        fun testGetNextTarget_queuedDevice() {
            val targets = listOf(
                createTarget(address = "DEV_1", slot = 0, state = DeviceScanState.COMPLETED),
                createTarget(address = "DEV_2", slot = 1, state = DeviceScanState.TESTING),
                createTarget(address = "DEV_3", state = DeviceScanState.QUEUED, slot = -1)
            )
            val session = ParallelScanSession(
                id = "test-session",
                config = defaultConfig,
                targets = targets,
                results = emptyList(),
                activeSlots = listOf("DEV_2"),
                totalDurationMs = 0L,
                completedCount = 1,
                failedCount = 0,
                cancelledCount = 0
            )

            val next = useCase.getNextTarget(session, freedSlot = 0)

            assertThat(next).isNotNull()
            assertThat(next!!.deviceAddress).isEqualTo("DEV_3")
            assertThat(next.assignedSlot).isEqualTo(0)
        }

        @Test
        @DisplayName("returns null when no queued devices remain")
        fun testGetNextTarget_noQueued_null() {
            val targets = listOf(
                createTarget(address = "DEV_1", state = DeviceScanState.COMPLETED, slot = 0),
                createTarget(address = "DEV_2", state = DeviceScanState.FAILED, slot = 1)
            )
            val session = ParallelScanSession(
                id = "test-session",
                config = defaultConfig,
                targets = targets,
                results = emptyList(),
                activeSlots = emptyList(),
                totalDurationMs = 0L,
                completedCount = 1,
                failedCount = 1,
                cancelledCount = 0
            )

            val next = useCase.getNextTarget(session, freedSlot = 0)

            assertThat(next).isNull()
        }
    }

    @Nested
    @DisplayName("updateTargetState")
    inner class UpdateTargetState {

        @Test
        @DisplayName("returns copy with updated state to CONNECTED")
        fun testUpdateTargetState_connected() {
            val target = createTarget(state = DeviceScanState.CONNECTING)

            val updated = useCase.updateTargetState(target, DeviceScanState.CONNECTED)

            assertThat(updated.state).isEqualTo(DeviceScanState.CONNECTED)
            assertThat(updated.deviceAddress).isEqualTo(target.deviceAddress)
            assertThat(updated.priority).isEqualTo(target.priority)
        }

        @Test
        @DisplayName("preserves all other fields when updating state")
        fun testUpdateTargetState_preservesFields() {
            val target = createTarget(
                address = "11:22:33:44:55:66",
                name = "MyDevice",
                priority = ScanPriority.HIGH,
                slot = 2,
                state = DeviceScanState.QUEUED
            )

            val updated = useCase.updateTargetState(target, DeviceScanState.SCANNING)

            assertThat(updated.deviceAddress).isEqualTo("11:22:33:44:55:66")
            assertThat(updated.deviceName).isEqualTo("MyDevice")
            assertThat(updated.priority).isEqualTo(ScanPriority.HIGH)
            assertThat(updated.assignedSlot).isEqualTo(2)
            assertThat(updated.state).isEqualTo(DeviceScanState.SCANNING)
        }
    }

    @Nested
    @DisplayName("computeProgress")
    inner class ComputeProgress {

        @Test
        @DisplayName("returns 0.5 when half the targets are complete")
        fun testComputeProgress_halfComplete() {
            val targets = listOf(
                createTarget(address = "D1", state = DeviceScanState.COMPLETED),
                createTarget(address = "D2", state = DeviceScanState.TESTING)
            )
            val session = ParallelScanSession(
                id = "test-session",
                config = defaultConfig,
                targets = targets,
                results = emptyList(),
                activeSlots = listOf("D2"),
                totalDurationMs = 0L,
                completedCount = 1,
                failedCount = 0,
                cancelledCount = 0
            )

            val progress = useCase.computeProgress(session)

            assertThat(progress).isWithin(0.01f).of(0.5f)
        }

        @Test
        @DisplayName("returns 1.0 when all targets are complete")
        fun testComputeProgress_allComplete() {
            val targets = listOf(
                createTarget(address = "D1", state = DeviceScanState.COMPLETED),
                createTarget(address = "D2", state = DeviceScanState.FAILED),
                createTarget(address = "D3", state = DeviceScanState.CANCELLED)
            )
            val session = ParallelScanSession(
                id = "test-session",
                config = defaultConfig,
                targets = targets,
                results = emptyList(),
                activeSlots = emptyList(),
                totalDurationMs = 5000L,
                completedCount = 1,
                failedCount = 1,
                cancelledCount = 1
            )

            val progress = useCase.computeProgress(session)

            assertThat(progress).isWithin(0.01f).of(1.0f)
        }

        @Test
        @DisplayName("returns 0.0 for empty targets")
        fun testComputeProgress_emptyTargets() {
            val session = ParallelScanSession(
                id = "test-session",
                config = defaultConfig,
                targets = emptyList(),
                results = emptyList(),
                activeSlots = emptyList(),
                totalDurationMs = 0L,
                completedCount = 0,
                failedCount = 0,
                cancelledCount = 0
            )

            val progress = useCase.computeProgress(session)

            assertThat(progress).isWithin(0.01f).of(0.0f)
        }
    }

    @Nested
    @DisplayName("computePoolStatus")
    inner class ComputePoolStatus {

        @Test
        @DisplayName("returns correct slot count and details")
        fun testComputePoolStatus_correctSlotCount() {
            val targets = listOf(
                createTarget(address = "D1", slot = 0, state = DeviceScanState.CONNECTED),
                createTarget(address = "D2", slot = 1, state = DeviceScanState.TESTING),
                createTarget(address = "D3", state = DeviceScanState.QUEUED)
            )
            val session = ParallelScanSession(
                id = "test-session",
                config = defaultConfig,
                targets = targets,
                results = emptyList(),
                activeSlots = listOf("D1", "D2"),
                totalDurationMs = 0L,
                completedCount = 0,
                failedCount = 0,
                cancelledCount = 0
            )

            val status = useCase.computePoolStatus(session)

            assertThat(status.totalSlots).isEqualTo(4)
            assertThat(status.activeSlots).isEqualTo(2)
            assertThat(status.queuedDevices).isEqualTo(1)
            assertThat(status.slotDetails).hasSize(4)
            assertThat(status.slotDetails[0].deviceAddress).isEqualTo("D1")
            assertThat(status.slotDetails[1].deviceAddress).isEqualTo("D2")
        }
    }

    @Nested
    @DisplayName("shouldStopSession")
    inner class ShouldStopSession {

        @Test
        @DisplayName("returns true when all targets are in terminal states")
        fun testShouldStopSession_allComplete() {
            val targets = listOf(
                createTarget(address = "D1", state = DeviceScanState.COMPLETED),
                createTarget(address = "D2", state = DeviceScanState.FAILED)
            )
            val session = ParallelScanSession(
                id = "test-session",
                config = defaultConfig,
                targets = targets,
                results = emptyList(),
                activeSlots = emptyList(),
                totalDurationMs = 0L,
                completedCount = 1,
                failedCount = 1,
                cancelledCount = 0
            )

            assertThat(useCase.shouldStopSession(session, defaultConfig)).isTrue()
        }

        @Test
        @DisplayName("stops when critical finding and stopOnFirstCritical enabled")
        fun testShouldStopSession_criticalFound_stopEnabled() {
            val targets = listOf(
                createTarget(address = "D1", state = DeviceScanState.COMPLETED),
                createTarget(address = "D2", state = DeviceScanState.TESTING)
            )
            val result = ParallelScanResult(
                target = targets[0],
                scanDurationMs = 1000L,
                servicesFound = 5,
                vulnerabilitiesFound = 2,
                criticalFindings = 1,
                highFindings = 1,
                testData = null
            )
            val session = ParallelScanSession(
                id = "test-session",
                config = defaultConfig.copy(stopOnFirstCritical = true),
                targets = targets,
                results = listOf(result),
                activeSlots = listOf("D2"),
                totalDurationMs = 0L,
                completedCount = 1,
                failedCount = 0,
                cancelledCount = 0
            )

            assertThat(useCase.shouldStopSession(session, session.config)).isTrue()
        }

        @Test
        @DisplayName("does not stop on critical finding when stopOnFirstCritical disabled")
        fun testShouldStopSession_criticalFound_stopDisabled() {
            val targets = listOf(
                createTarget(address = "D1", state = DeviceScanState.COMPLETED),
                createTarget(address = "D2", state = DeviceScanState.TESTING)
            )
            val result = ParallelScanResult(
                target = targets[0],
                scanDurationMs = 1000L,
                servicesFound = 5,
                vulnerabilitiesFound = 2,
                criticalFindings = 1,
                highFindings = 1,
                testData = null
            )
            val session = ParallelScanSession(
                id = "test-session",
                config = defaultConfig.copy(stopOnFirstCritical = false),
                targets = targets,
                results = listOf(result),
                activeSlots = listOf("D2"),
                totalDurationMs = 0L,
                completedCount = 1,
                failedCount = 0,
                cancelledCount = 0
            )

            assertThat(useCase.shouldStopSession(session, session.config)).isFalse()
        }

        @Test
        @DisplayName("returns false when targets still active and no critical")
        fun testShouldStopSession_activeTargets() {
            val targets = listOf(
                createTarget(address = "D1", state = DeviceScanState.TESTING),
                createTarget(address = "D2", state = DeviceScanState.QUEUED)
            )
            val session = ParallelScanSession(
                id = "test-session",
                config = defaultConfig,
                targets = targets,
                results = emptyList(),
                activeSlots = listOf("D1"),
                totalDurationMs = 0L,
                completedCount = 0,
                failedCount = 0,
                cancelledCount = 0
            )

            assertThat(useCase.shouldStopSession(session, defaultConfig)).isFalse()
        }
    }

    @Nested
    @DisplayName("generateSessionReport")
    inner class GenerateSessionReport {

        @Test
        @DisplayName("returns non-empty report with session details")
        fun testGenerateSessionReport_notEmpty() {
            val targets = listOf(
                createTarget(address = "D1", state = DeviceScanState.COMPLETED),
                createTarget(address = "D2", state = DeviceScanState.FAILED)
            )
            val result = ParallelScanResult(
                target = targets[0],
                scanDurationMs = 5000L,
                servicesFound = 8,
                vulnerabilitiesFound = 3,
                criticalFindings = 1,
                highFindings = 2,
                testData = null
            )
            val session = ParallelScanSession(
                id = "report-session-123",
                config = defaultConfig,
                targets = targets,
                results = listOf(result),
                activeSlots = emptyList(),
                totalDurationMs = 10000L,
                completedCount = 1,
                failedCount = 1,
                cancelledCount = 0
            )

            val report = useCase.generateSessionReport(session)

            assertThat(report).isNotEmpty()
            assertThat(report).contains("report-session-123")
            assertThat(report).contains("2 total")
            assertThat(report).contains("1 completed")
            assertThat(report).contains("1 failed")
            assertThat(report).contains("3")
            assertThat(report).contains("1 critical")
            assertThat(report).contains("2 high")
        }
    }

    @Nested
    @DisplayName("sortTargetsByPriority")
    inner class SortTargetsByPriority {

        @Test
        @DisplayName("sorts CRITICAL targets first")
        fun testSortTargetsByPriority_criticalFirst() {
            val targets = listOf(
                createTarget(address = "LOW", priority = ScanPriority.LOW),
                createTarget(address = "CRIT", priority = ScanPriority.CRITICAL),
                createTarget(address = "HIGH", priority = ScanPriority.HIGH),
                createTarget(address = "NORM", priority = ScanPriority.NORMAL)
            )

            val sorted = useCase.sortTargetsByPriority(targets)

            assertThat(sorted).hasSize(4)
            assertThat(sorted[0].priority).isEqualTo(ScanPriority.CRITICAL)
            assertThat(sorted[1].priority).isEqualTo(ScanPriority.HIGH)
            assertThat(sorted[2].priority).isEqualTo(ScanPriority.NORMAL)
            assertThat(sorted[3].priority).isEqualTo(ScanPriority.LOW)
        }

        @Test
        @DisplayName("preserves relative order of targets with same priority")
        fun testSortTargetsByPriority_preservesOrder() {
            val targets = listOf(
                createTarget(address = "NORM_1", priority = ScanPriority.NORMAL),
                createTarget(address = "CRIT_1", priority = ScanPriority.CRITICAL),
                createTarget(address = "NORM_2", priority = ScanPriority.NORMAL),
                createTarget(address = "CRIT_2", priority = ScanPriority.CRITICAL),
                createTarget(address = "NORM_3", priority = ScanPriority.NORMAL)
            )

            val sorted = useCase.sortTargetsByPriority(targets)

            // CRITICAL first, in original order
            assertThat(sorted[0].deviceAddress).isEqualTo("CRIT_1")
            assertThat(sorted[1].deviceAddress).isEqualTo("CRIT_2")
            // Then NORMAL, in original order
            assertThat(sorted[2].deviceAddress).isEqualTo("NORM_1")
            assertThat(sorted[3].deviceAddress).isEqualTo("NORM_2")
            assertThat(sorted[4].deviceAddress).isEqualTo("NORM_3")
        }

        @Test
        @DisplayName("returns empty list for empty input")
        fun testSortTargetsByPriority_empty() {
            val sorted = useCase.sortTargetsByPriority(emptyList())
            assertThat(sorted).isEmpty()
        }

        @Test
        @DisplayName("handles single target")
        fun testSortTargetsByPriority_single() {
            val targets = listOf(
                createTarget(address = "ONLY", priority = ScanPriority.HIGH)
            )
            val sorted = useCase.sortTargetsByPriority(targets)

            assertThat(sorted).hasSize(1)
            assertThat(sorted[0].deviceAddress).isEqualTo("ONLY")
        }
    }
}
