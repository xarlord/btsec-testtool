/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.model

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * Domain models for the Custom Test Scripting DSL.
 *
 * Defines test scripts composed of steps (scan, connect, read, write, fuzz, etc.)
 * with validation, execution state tracking, and variable substitution.
 * Only to be used for AUTHORIZED security testing purposes.
 */

internal val scriptJson = Json { ignoreUnknownKeys = true; encodeDefaults = true }

fun encodeTestScriptToString(script: TestScript): String =
    scriptJson.encodeToString(TestScript.serializer(), script)

fun decodeTestScriptFromString(json: String): TestScript =
    scriptJson.decodeFromString(TestScript.serializer(), json)

@Serializable
enum class ScriptStepType {
    SCAN, CONNECT, DISCONNECT, READ, WRITE, SUBSCRIBE, FUZZ,
    ASSERT, WAIT, LOG, LOOP, CONDITION, VARIABLE_SET, VARIABLE_GET,
    SERVICE_DISCOVERY, PAIR, UNPAIR
}

@Serializable
data class ScriptStep(
    val type: ScriptStepType,
    val params: Map<String, String> = emptyMap(),
    val label: String? = null,
    val onError: ErrorAction = ErrorAction.STOP,
    val timeout: Long = 10000
)

@Serializable
enum class ErrorAction { STOP, SKIP, RETRY, CONTINUE }

@Serializable
data class ScriptVariable(
    val name: String,
    val value: String,
    val type: VariableType = VariableType.STRING
)

@Serializable
enum class VariableType { STRING, INTEGER, BOOLEAN, BYTES }

@Serializable
data class TestScript(
    val name: String,
    val description: String = "",
    val author: String? = null,
    val version: Int = 1,
    val targetDevice: String? = null,
    val steps: List<ScriptStep> = emptyList(),
    val variables: List<ScriptVariable> = emptyList(),
    val timeout: Long = 60000,
    val tags: List<String> = emptyList()
)

@Serializable
enum class ScriptValidationSeverity { ERROR, WARNING, INFO }

@Serializable
data class ScriptValidation(
    val severity: ScriptValidationSeverity,
    val message: String,
    val stepIndex: Int? = null
)

@Serializable
data class ScriptExecution(
    val id: String,
    val script: TestScript,
    val startTime: Long,
    val endTime: Long? = null,
    val currentStep: Int = 0,
    val state: ExecutionState = ExecutionState.PENDING,
    val stepResults: List<StepResult> = emptyList(),
    val variables: Map<String, String> = emptyMap()
)

@Serializable
enum class ExecutionState {
    PENDING, RUNNING, PAUSED, COMPLETED, FAILED, CANCELLED
}

@Serializable
data class StepResult(
    val stepIndex: Int,
    val stepType: ScriptStepType,
    val success: Boolean,
    val startTime: Long,
    val endTime: Long,
    val output: String? = null,
    val error: String? = null
)
