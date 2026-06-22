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
 * Represents a YAML-defined test script for automated BLE security testing.
 *
 * Users can write YAML scripts in any text editor and import them into the app.
 * The YAML format maps to the existing ScriptModels test script structure.
 * Used for AUTHORIZED security testing of BLE devices.
 */
data class YamlTestScript(
    val name: String,
    val description: String,
    val author: String? = null,
    val version: Int = 1,
    val target: String? = null,
    val timeout: Long = 60000,
    val tags: List<String> = emptyList(),
    val variables: Map<String, String> = emptyMap(),
    val steps: List<YamlStep>,
)

/**
 * A single step in a YAML test script.
 *
 * Each step defines an action to perform during AUTHORIZED BLE security testing.
 * Steps can be nested via substeps for loops and conditional execution.
 */
data class YamlStep(
    // "scan", "connect", "read", "write", etc.
    val action: String,
    val params: Map<String, String> = emptyMap(),
    val label: String? = null,
    // "stop", "skip", "retry", "continue"
    val `continue`: String = "stop",
    val timeout: Long = 10000,
    // Number of times to repeat this step
    val repeat: Int = 1,
    // Condition expression
    val `if`: String? = null,
    // For loops/conditions
    val substeps: List<YamlStep> = emptyList(),
)

/**
 * Represents a parsing error or warning encountered during YAML processing.
 */
data class YamlParseError(
    val line: Int,
    val column: Int,
    val message: String,
    val severity: YamlErrorSeverity,
)

/**
 * Severity levels for YAML parsing issues.
 */
enum class YamlErrorSeverity { ERROR, WARNING }

/**
 * Result of parsing a YAML test script.
 *
 * Contains the parsed script (null if fatal errors occurred),
 * plus any errors and warnings encountered during parsing.
 */
data class YamlParseResult(
    val script: YamlTestScript?,
    val errors: List<YamlParseError>,
    val warnings: List<YamlParseError>,
)
