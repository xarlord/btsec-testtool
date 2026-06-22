/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.ScriptStep
import com.btsec.testtool.domain.model.ScriptStepType
import com.btsec.testtool.domain.model.ScriptValidation
import com.btsec.testtool.domain.model.ScriptValidationSeverity
import com.btsec.testtool.domain.model.TestScript
import com.btsec.testtool.domain.model.decodeTestScriptFromString
import com.btsec.testtool.domain.model.encodeTestScriptToString
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Use case for the Custom Test Scripting DSL.
 *
 * Provides script validation, variable resolution, step creation, duration estimation,
 * template generation, and JSON serialization/deserialization.
 * Only to be used for AUTHORIZED security testing purposes.
 */
@Singleton
class ScriptingDslUseCase
    @Inject
    constructor() {
        companion object {
            private val VARIABLE_REGEX = Regex("""\$\{([^}]+)}""")
            private const val MAX_LOOP_ITERATIONS_WARNING = 1000
            private const val MAX_TIMEOUT_WARNING_MS = 300_000L // 5 minutes

            private val REQUIRES_CONNECTION =
                setOf(
                    ScriptStepType.READ,
                    ScriptStepType.WRITE,
                    ScriptStepType.SUBSCRIBE,
                    ScriptStepType.SERVICE_DISCOVERY,
                    ScriptStepType.PAIR,
                    ScriptStepType.UNPAIR,
                )
        }

        /**
         * Validate a test script and return a list of validation results.
         */
        fun validateScript(script: TestScript): List<ScriptValidation> {
            val validations = mutableListOf<ScriptValidation>()

            // Script must have at least 1 step
            if (script.steps.isEmpty()) {
                validations.add(
                    ScriptValidation(
                        severity = ScriptValidationSeverity.ERROR,
                        message = "Script must contain at least one step",
                    ),
                )
                return validations
            }

            var connected = false

            script.steps.forEachIndexed { index, step ->
                // Check for disconnected operations
                if (step.type in REQUIRES_CONNECTION && !connected) {
                    validations.add(
                        ScriptValidation(
                            severity = ScriptValidationSeverity.ERROR,
                            message = "Step ${step.type.name} at index $index requires a prior CONNECT step",
                            stepIndex = index,
                        ),
                    )
                }

                if (step.type == ScriptStepType.CONNECT) {
                    connected = true
                }
                if (step.type == ScriptStepType.DISCONNECT) {
                    connected = false
                }

                // Check loop bounds
                if (step.type == ScriptStepType.LOOP) {
                    val maxIter = step.params["maxIterations"]?.toLongOrNull()
                    if (maxIter == null) {
                        validations.add(
                            ScriptValidation(
                                severity = ScriptValidationSeverity.ERROR,
                                message = "LOOP at index $index has no maxIterations bound (possible infinite loop)",
                                stepIndex = index,
                            ),
                        )
                    } else if (maxIter > MAX_LOOP_ITERATIONS_WARNING) {
                        validations.add(
                            ScriptValidation(
                                severity = ScriptValidationSeverity.WARNING,
                                message = "LOOP at index $index has $maxIter iterations (exceeds $MAX_LOOP_ITERATIONS_WARNING)",
                                stepIndex = index,
                            ),
                        )
                    }
                }

                // Check ASSERT has expected value
                if (step.type == ScriptStepType.ASSERT) {
                    if (!step.params.containsKey("expected") && !step.params.containsKey("expectedValue")) {
                        validations.add(
                            ScriptValidation(
                                severity = ScriptValidationSeverity.ERROR,
                                message = "ASSERT at index $index is missing 'expected' or 'expectedValue' parameter",
                                stepIndex = index,
                            ),
                        )
                    }
                }

                // Check variable references exist
                val varRefs = extractVariableReferences(step.params.values)
                val definedVars = script.variables.map { it.name }.toSet()
                val stepVarDefs = mutableSetOf<String>()
                for (i in 0..index) {
                    if (script.steps[i].type == ScriptStepType.VARIABLE_SET) {
                        script.steps[i].params["name"]?.let { stepVarDefs.add(it) }
                    }
                }
                val allDefined = definedVars + stepVarDefs
                for (ref in varRefs) {
                    if (ref !in allDefined) {
                        validations.add(
                            ScriptValidation(
                                severity = ScriptValidationSeverity.ERROR,
                                message = "Undefined variable reference '\${$ref}' in step at index $index",
                                stepIndex = index,
                            ),
                        )
                    }
                }
            }

            // Check script-level timeout
            if (script.timeout > MAX_TIMEOUT_WARNING_MS) {
                validations.add(
                    ScriptValidation(
                        severity = ScriptValidationSeverity.WARNING,
                        message = "Script timeout ${script.timeout}ms exceeds ${MAX_TIMEOUT_WARNING_MS}ms (5 minutes)",
                    ),
                )
            }

            // Check for DISCONNECT at end (good practice)
            if (script.steps.isNotEmpty()) {
                val hasDisconnect = script.steps.any { it.type == ScriptStepType.DISCONNECT }
                if (!hasDisconnect) {
                    validations.add(
                        ScriptValidation(
                            severity = ScriptValidationSeverity.INFO,
                            message = "Script does not contain a DISCONNECT step (recommended for cleanup)",
                        ),
                    )
                }
            }

            return validations
        }

        /**
         * Resolve ${varName} placeholders in a string using the provided variable map.
         */
        fun resolveVariable(
            value: String,
            variables: Map<String, String>,
        ): String {
            return VARIABLE_REGEX.replace(value) { match ->
                val varName = match.groupValues[1]
                variables[varName] ?: match.value
            }
        }

        /**
         * Factory method to create a ScriptStep with the given type and params.
         */
        fun createStep(
            type: ScriptStepType,
            params: Map<String, String>,
        ): ScriptStep {
            return ScriptStep(type = type, params = params)
        }

        /**
         * Estimate total execution duration in milliseconds by summing step timeouts
         * and explicit WAIT durations.
         */
        fun estimateDuration(script: TestScript): Long {
            var total = 0L
            for (step in script.steps) {
                total += step.timeout
                if (step.type == ScriptStepType.WAIT) {
                    val waitMs = step.params["duration"]?.toLongOrNull() ?: 0L
                    total += waitMs
                }
                if (step.type == ScriptStepType.LOOP) {
                    val iterations = step.params["maxIterations"]?.toLongOrNull() ?: 1L
                    // Rough estimate: loop body timeout * iterations
                    total += step.timeout * (iterations - 1)
                }
            }
            return total
        }

        /**
         * Return template steps for each ScriptStepType with sensible default params.
         */
        fun getStepTemplates(): List<ScriptStep> {
            return ScriptStepType.entries.map { type ->
                ScriptStep(
                    type = type,
                    params = defaultParamsFor(type),
                )
            }
        }

        /**
         * Deserialize a TestScript from a JSON string.
         */
        fun parseScriptFromJson(json: String): TestScript? {
            return try {
                decodeTestScriptFromString(json)
            } catch (_: Exception) {
                null
            }
        }

        /**
         * Serialize a TestScript to a JSON string.
         */
        fun serializeScriptToJson(script: TestScript): String {
            return encodeTestScriptToString(script)
        }

        // ── Internal helpers ──

        private fun extractVariableReferences(values: Collection<String>): Set<String> {
            val refs = mutableSetOf<String>()
            val regex = VARIABLE_REGEX
            for (value in values) {
                regex.findAll(value).forEach { match ->
                    refs.add(match.groupValues[1])
                }
            }
            return refs
        }

        private fun defaultParamsFor(type: ScriptStepType): Map<String, String> {
            return when (type) {
                ScriptStepType.SCAN -> mapOf("duration" to "5000", "filter" to "")
                ScriptStepType.CONNECT -> mapOf("address" to "")
                ScriptStepType.DISCONNECT -> emptyMap()
                ScriptStepType.READ -> mapOf("service" to "", "characteristic" to "")
                ScriptStepType.WRITE -> mapOf("service" to "", "characteristic" to "", "value" to "")
                ScriptStepType.SUBSCRIBE -> mapOf("service" to "", "characteristic" to "")
                ScriptStepType.FUZZ -> mapOf("service" to "", "packetCount" to "100")
                ScriptStepType.ASSERT -> mapOf("field" to "", "expected" to "")
                ScriptStepType.WAIT -> mapOf("duration" to "1000")
                ScriptStepType.LOG -> mapOf("message" to "")
                ScriptStepType.LOOP -> mapOf("maxIterations" to "10", "startIndex" to "0")
                ScriptStepType.CONDITION -> mapOf("variable" to "", "value" to "")
                ScriptStepType.VARIABLE_SET -> mapOf("name" to "", "value" to "")
                ScriptStepType.VARIABLE_GET -> mapOf("name" to "")
                ScriptStepType.SERVICE_DISCOVERY -> emptyMap()
                ScriptStepType.PAIR -> mapOf("address" to "")
                ScriptStepType.UNPAIR -> mapOf("address" to "")
            }
        }
    }
