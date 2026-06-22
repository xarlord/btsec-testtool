/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.YamlErrorSeverity
import com.btsec.testtool.domain.model.YamlParseError
import com.btsec.testtool.domain.model.YamlParseResult
import com.btsec.testtool.domain.model.YamlStep
import com.btsec.testtool.domain.model.YamlTestScript
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Use case for parsing and validating YAML-based BLE test scripts.
 *
 * Provides a lightweight YAML parser (no external dependency) that converts
 * YAML text into [YamlTestScript] objects for automated BLE security testing.
 * All operations are designed for AUTHORIZED security testing only.
 */
@Singleton
class YamlScriptingUseCase
    @Inject
    constructor() {
        companion object {
            private val VALID_ACTIONS =
                setOf(
                    "scan", "connect", "disconnect", "read", "write",
                    "subscribe", "fuzz", "assert", "wait", "log",
                    "service_discovery", "pair", "unpair",
                )

            private val ACTIONS_REQUIRING_CONNECT =
                setOf(
                    "read",
                    "write",
                    "fuzz",
                    "subscribe",
                    "service_discovery",
                    "pair",
                    "unpair",
                )

            private val VARIABLE_REF_REGEX = Regex("""\$\{(\w+)}""")
        }

        /**
         * Parse YAML text into a [YamlParseResult].
         *
         * Simple parser that handles:
         * 1. Key: value pairs
         * 2. Indentation-based nesting
         * 3. List items (lines starting with -)
         * 4. Inline flow sequences [a, b, c]
         * 5. Quoted and unquoted string values
         */
        fun parseYaml(yamlText: String): YamlParseResult {
            val errors = mutableListOf<YamlParseError>()
            val warnings = mutableListOf<YamlParseError>()

            if (yamlText.isBlank()) {
                errors.add(
                    YamlParseError(
                        line = 1,
                        column = 1,
                        message = "YAML input is empty",
                        severity = YamlErrorSeverity.ERROR,
                    ),
                )
                return YamlParseResult(script = null, errors = errors, warnings = warnings)
            }

            val lines = yamlText.lines()
            val rootMap = mutableMapOf<String, Any>()
            parseBlock(lines, 0, lines.size, 0, rootMap, errors, warnings)

            // Extract fields from parsed map
            val name = (rootMap["name"] as? String) ?: ""
            val description = (rootMap["description"] as? String) ?: ""
            val author = rootMap["author"] as? String
            val version = (rootMap["version"] as? Number)?.toInt() ?: 1
            val target = rootMap["target"] as? String
            val timeout = (rootMap["timeout"] as? Number)?.toLong() ?: 60000L
            val tags = (rootMap["tags"] as? List<*>)?.mapNotNull { it?.toString() } ?: emptyList()
            val variables =
                (rootMap["variables"] as? Map<*, *>)?.entries?.associate {
                    it.key.toString() to it.value.toString()
                } ?: emptyMap()

            if (name.isBlank()) {
                warnings.add(
                    YamlParseError(
                        line = 1,
                        column = 1,
                        message = "Script name is missing or empty",
                        severity = YamlErrorSeverity.WARNING,
                    ),
                )
            }

            @Suppress("UNCHECKED_CAST")
            val rawSteps = rootMap["steps"] as? List<Map<String, Any>> ?: emptyList()
            val steps =
                rawSteps.mapIndexed { index, raw ->
                    parseStep(raw, index, errors)
                }

            if (steps.isEmpty()) {
                errors.add(
                    YamlParseError(
                        line = 1,
                        column = 1,
                        message = "Script has no steps defined",
                        severity = YamlErrorSeverity.ERROR,
                    ),
                )
                return YamlParseResult(script = null, errors = errors, warnings = warnings)
            }

            val script =
                YamlTestScript(
                    name = name,
                    description = description,
                    author = author,
                    version = version,
                    target = target,
                    timeout = timeout,
                    tags = tags,
                    variables = variables,
                    steps = steps,
                )

            return YamlParseResult(
                script = if (errors.isEmpty()) script else null,
                errors = errors,
                warnings = warnings,
            )
        }

        /**
         * Validate a parsed [YamlTestScript].
         *
         * Checks:
         * - name is non-empty
         * - has at least 1 step
         * - all actions are valid
         * - connect appears before read/write/fuzz
         * - variable references exist in variables map
         * - repeat is positive
         * - timeout is positive
         */
        fun validateYamlScript(script: YamlTestScript): List<YamlParseError> {
            val errors = mutableListOf<YamlParseError>()

            if (script.name.isBlank()) {
                errors.add(
                    YamlParseError(
                        line = 1,
                        column = 1,
                        message = "Script name must not be empty",
                        severity = YamlErrorSeverity.ERROR,
                    ),
                )
            }

            if (script.steps.isEmpty()) {
                errors.add(
                    YamlParseError(
                        line = 1,
                        column = 1,
                        message = "Script must have at least one step",
                        severity = YamlErrorSeverity.ERROR,
                    ),
                )
            }

            var hasConnected = false
            val allVariables = script.variables.keys

            for ((index, step) in script.steps.withIndex()) {
                val stepNum = index + 1
                if (step.action !in VALID_ACTIONS) {
                    errors.add(
                        YamlParseError(
                            line = stepNum,
                            column = 1,
                            message = "Invalid action '${step.action}' at step $stepNum. Valid actions: ${VALID_ACTIONS.sorted().joinToString(
                                ", ",
                            )}",
                            severity = YamlErrorSeverity.ERROR,
                        ),
                    )
                }

                if (step.action == "connect") {
                    hasConnected = true
                }

                if (step.action in ACTIONS_REQUIRING_CONNECT && !hasConnected) {
                    errors.add(
                        YamlParseError(
                            line = stepNum,
                            column = 1,
                            message = "Step $stepNum uses action '${step.action}' but no connect step precedes it",
                            severity = YamlErrorSeverity.ERROR,
                        ),
                    )
                }

                if (step.repeat < 1) {
                    errors.add(
                        YamlParseError(
                            line = stepNum,
                            column = 1,
                            message = "Step $stepNum has repeat count ${step.repeat}; must be positive",
                            severity = YamlErrorSeverity.ERROR,
                        ),
                    )
                }

                if (step.timeout < 0) {
                    errors.add(
                        YamlParseError(
                            line = stepNum,
                            column = 1,
                            message = "Step $stepNum has negative timeout ${step.timeout}",
                            severity = YamlErrorSeverity.ERROR,
                        ),
                    )
                }

                // Check variable references in params
                for ((key, value) in step.params) {
                    val refs = VARIABLE_REF_REGEX.findAll(value)
                    for (ref in refs) {
                        val varName = ref.groupValues[1]
                        if (varName !in allVariables && varName != "target") {
                            errors.add(
                                YamlParseError(
                                    line = stepNum,
                                    column = 1,
                                    message = "Step $stepNum references undefined variable '\${$varName}' in param '$key'",
                                    severity = YamlErrorSeverity.ERROR,
                                ),
                            )
                        }
                    }
                }

                // Recursively validate substeps
                validateSubsteps(step.substeps, stepNum, hasConnected, allVariables, errors)
            }

            return errors
        }

        private fun validateSubsteps(
            substeps: List<YamlStep>,
            parentStepNum: Int,
            parentHasConnected: Boolean,
            allVariables: Set<String>,
            errors: MutableList<YamlParseError>,
        ) {
            var hasConnected = parentHasConnected
            for ((subIndex, substep) in substeps.withIndex()) {
                val subNum = "$parentStepNum.${subIndex + 1}"
                if (substep.action !in VALID_ACTIONS) {
                    errors.add(
                        YamlParseError(
                            line = 0,
                            column = 1,
                            message = "Invalid action '${substep.action}' in substep $subNum",
                            severity = YamlErrorSeverity.ERROR,
                        ),
                    )
                }
                if (substep.action == "connect") hasConnected = true
                if (substep.action in ACTIONS_REQUIRING_CONNECT && !hasConnected) {
                    errors.add(
                        YamlParseError(
                            line = 0,
                            column = 1,
                            message = "Substep $subNum uses '${substep.action}' but no connect precedes it",
                            severity = YamlErrorSeverity.ERROR,
                        ),
                    )
                }
                for ((key, value) in substep.params) {
                    for (ref in VARIABLE_REF_REGEX.findAll(value)) {
                        val varName = ref.groupValues[1]
                        if (varName !in allVariables && varName != "target") {
                            errors.add(
                                YamlParseError(
                                    line = 0,
                                    column = 1,
                                    message = "Substep $subNum references undefined variable '\${$varName}' in param '$key'",
                                    severity = YamlErrorSeverity.ERROR,
                                ),
                            )
                        }
                    }
                }
                validateSubsteps(substep.substeps, subNum.toInt(), hasConnected, allVariables, errors)
            }
        }

        /**
         * Replace ${varName} placeholders in text with values from the variables map.
         * Unknown variable references are left unchanged.
         */
        fun resolveVariables(
            text: String,
            variables: Map<String, String>,
        ): String {
            return VARIABLE_REF_REGEX.replace(text) { match ->
                val varName = match.groupValues[1]
                variables[varName] ?: match.value
            }
        }

        /**
         * Return a sample YAML test script as a string template.
         */
        fun getYamlTemplate(): String {
            return """
            |name: "BLE Security Test Template"
            |description: "Template for AUTHORIZED BLE security testing"
            |author: "Security Researcher"
            |version: 1
            |target: "AA:BB:CC:DD:EE:FF"
            |timeout: 60000
            |tags: [ble, security, template]
            |variables:
            |  service_uuid: "180D"
            |  char_uuid: "2A37"
            |steps:
            |  - action: scan
            |    timeout: 10000
            |    label: "Scan for BLE devices"
            |  - action: connect
            |    params:
            |      address: "${'$'}{target}"
            |    label: "Connect to target device"
            |  - action: service_discovery
            |    label: "Discover available services"
            |  - action: read
            |    params:
            |      service: "${'$'}{service_uuid}"
            |      characteristic: "${'$'}{char_uuid}"
            |    label: "Read heart rate measurement"
            |  - action: write
            |    params:
            |      service: "${'$'}{service_uuid}"
            |      characteristic: "2A39"
            |      value: "0x01"
            |    label: "Write test value"
            |  - action: fuzz
            |    params:
            |      service: "${'$'}{service_uuid}"
            |      characteristic: "2A39"
            |      iterations: "100"
            |    label: "Fuzz characteristic"
            |  - action: assert
            |    params:
            |      expected: "success"
            |    label: "Verify operation succeeded"
            |  - action: disconnect
            |    label: "Disconnect from device"
                """.trimMargin()
        }

        /**
         * Map action names to descriptions for documentation/reference.
         */
        fun getYamlActionReference(): Map<String, String> {
            return mapOf(
                "scan" to "Scan for nearby BLE devices",
                "connect" to "Connect to a BLE device by address",
                "disconnect" to "Disconnect from the current BLE device",
                "read" to "Read a characteristic value from a service",
                "write" to "Write a value to a characteristic",
                "subscribe" to "Subscribe to characteristic notifications/indications",
                "fuzz" to "Fuzz a characteristic with random or malformed data",
                "assert" to "Assert an expected condition or result",
                "wait" to "Wait for a specified duration",
                "log" to "Log a message to the test output",
                "service_discovery" to "Discover services and characteristics on the connected device",
                "pair" to "Pair with the connected BLE device",
                "unpair" to "Unpair from the connected BLE device",
            )
        }

        // --- Internal parser helpers ---

        private fun parseBlock(
            lines: List<String>,
            start: Int,
            end: Int,
            baseIndent: Int,
            target: MutableMap<String, Any>,
            errors: MutableList<YamlParseError>,
            warnings: MutableList<YamlParseError>,
        ) {
            var i = start
            while (i < end) {
                val line = lines[i]
                val trimmed = line.trimStart()
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    i++
                    continue
                }

                val indent = line.length - line.trimStart().length
                if (indent < baseIndent) break

                // List item
                if (trimmed.startsWith("- ")) {
                    break // list items handled separately
                }

                // Key: value pair
                val colonIdx = trimmed.indexOf(':').takeIf { it >= 0 }
                if (colonIdx != null) {
                    val key = trimmed.substring(0, colonIdx).trim()
                    val rawValue = trimmed.substring(colonIdx + 1).trim()

                    if (rawValue.isEmpty() || rawValue.startsWith("#")) {
                        // Block-style value (map or list follows)
                        val childStart = i + 1
                        val childIndent = indent + 2

                        // Find the extent of this block
                        var childEnd = childStart
                        while (childEnd < end) {
                            val childLine = lines[childEnd]
                            val childTrimmed = childLine.trimStart()
                            if (childTrimmed.isEmpty() || childTrimmed.startsWith("#")) {
                                childEnd++
                                continue
                            }
                            val childIndentActual = childLine.length - childLine.trimStart().length
                            if (childIndentActual < childIndent) break
                            childEnd++
                        }

                        // Check if it's a list block
                        val isList =
                            if (childStart < childEnd) {
                                val firstContentLine =
                                    lines.subList(childStart, childEnd)
                                        .firstOrNull { it.trimStart().isNotEmpty() && !it.trimStart().startsWith("#") }
                                firstContentLine?.trimStart()?.startsWith("- ") == true
                            } else {
                                false
                            }

                        if (isList) {
                            val listItems = parseListBlock(lines, childStart, childEnd, childIndent, errors, warnings)
                            target[key] = listItems
                        } else {
                            val childMap = mutableMapOf<String, Any>()
                            parseBlock(lines, childStart, childEnd, childIndent, childMap, errors, warnings)
                            if (childMap.isNotEmpty()) {
                                target[key] = childMap
                            }
                        }
                        i = childEnd
                    } else {
                        // Inline value
                        target[key] = parseValue(rawValue)
                        i++
                    }
                } else {
                    i++
                }
            }
        }

        private fun parseListBlock(
            lines: List<String>,
            start: Int,
            end: Int,
            expectedIndent: Int,
            errors: MutableList<YamlParseError>,
            warnings: MutableList<YamlParseError>,
        ): List<Map<String, Any>> {
            val items = mutableListOf<Map<String, Any>>()
            var i = start

            while (i < end) {
                val line = lines[i]
                val trimmed = line.trimStart()
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    i++
                    continue
                }

                val indent = line.length - line.trimStart().length
                if (indent < expectedIndent) break

                if (trimmed.startsWith("- ")) {
                    val itemMap = mutableMapOf<String, Any>()
                    // Parse the rest of the "- " line as key: value
                    val afterDash = trimmed.substring(2).trim()
                    val colonIdx = afterDash.indexOf(':').takeIf { it >= 0 }
                    if (colonIdx != null) {
                        val key = afterDash.substring(0, colonIdx).trim()
                        val rawValue = afterDash.substring(colonIdx + 1).trim()
                        if (rawValue.isNotEmpty()) {
                            itemMap[key] = parseValue(rawValue)
                        } else {
                            // Empty value after colon on list item line - might be a nested block
                            // Treat as empty; subsequent indented lines will be parsed below
                        }
                    }

                    // Collect continuation lines for this list item
                    val itemIndent = indent
                    val continuationStart = i + 1
                    var continuationEnd = continuationStart
                    while (continuationEnd < end) {
                        val cLine = lines[continuationEnd]
                        val cTrimmed = cLine.trimStart()
                        if (cTrimmed.isEmpty() || cTrimmed.startsWith("#")) {
                            continuationEnd++
                            continue
                        }
                        val cIndent = cLine.length - cLine.trimStart().length
                        if (cIndent <= itemIndent) break
                        continuationEnd++
                    }

                    // Parse continuation lines as the item's properties
                    if (continuationStart < continuationEnd) {
                        val contIndent = itemIndent + 2
                        parseBlock(lines, continuationStart, continuationEnd, contIndent, itemMap, errors, warnings)
                    }

                    items.add(itemMap)
                    i = continuationEnd
                } else {
                    i++
                }
            }

            return items
        }

        private fun parseValue(raw: String): Any {
            // Handle flow-style list [a, b, c]
            if (raw.startsWith("[") && raw.endsWith("]")) {
                return raw.substring(1, raw.length - 1)
                    .split(",")
                    .map { it.trim().removeSurrounding("\"").removeSurrounding("'") }
                    .filter { it.isNotEmpty() }
            }

            // Handle quoted strings
            val unquoted = raw.removeSurrounding("\"").removeSurrounding("'")

            // Try integer
            unquoted.toIntOrNull()?.let { return it }

            // Try long
            unquoted.toLongOrNull()?.let { return it }

            // Boolean
            return when (unquoted.lowercase()) {
                "true" -> true
                "false" -> false
                "null" -> "" // treat null as empty string
                else -> unquoted
            }
        }

        private fun parseStep(
            raw: Map<String, Any>,
            index: Int,
            errors: MutableList<YamlParseError>,
        ): YamlStep {
            val action = (raw["action"] as? String) ?: ""
            val label = raw["label"] as? String
            val continueVal = (raw["continue"] as? String) ?: "stop"
            val timeout = (raw["timeout"] as? Number)?.toLong() ?: 10000L
            val repeat = (raw["repeat"] as? Number)?.toInt() ?: 1
            val condition = raw["if"] as? String

            @Suppress("UNCHECKED_CAST")
            val params =
                (raw["params"] as? Map<String, Any>)?.mapValues {
                    it.value.toString()
                } ?: emptyMap()

            @Suppress("UNCHECKED_CAST")
            val rawSubsteps = raw["substeps"] as? List<Map<String, Any>> ?: emptyList()
            val substeps =
                rawSubsteps.mapIndexed { subIndex, subRaw ->
                    parseStep(subRaw, subIndex, errors)
                }

            return YamlStep(
                action = action,
                params = params,
                label = label,
                `continue` = continueVal,
                timeout = timeout,
                repeat = repeat,
                `if` = condition,
                substeps = substeps,
            )
        }
    }
