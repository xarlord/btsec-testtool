/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.ErrorAction
import com.btsec.testtool.domain.model.ScriptStep
import com.btsec.testtool.domain.model.ScriptStepType
import com.btsec.testtool.domain.model.ScriptValidationSeverity
import com.btsec.testtool.domain.model.TestScript
import com.btsec.testtool.domain.model.ScriptVariable
import com.btsec.testtool.domain.model.VariableType
import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

/**
 * Unit tests for [ScriptingDslUseCase].
 *
 * Covers script validation, variable resolution, step creation, duration estimation,
 * template generation, and JSON round-trip serialization.
 * Only for AUTHORIZED security testing purposes.
 */
class ScriptingDslUseCaseTest {

    private lateinit var useCase: ScriptingDslUseCase

    @BeforeEach
    fun setUp() {
        useCase = ScriptingDslUseCase()
    }

    // ── Validation tests ──

    @Test
    @DisplayName("validateScript with empty steps returns ERROR")
    fun testValidateScript_emptySteps_error() {
        val script = TestScript(name = "empty", steps = emptyList())
        val validations = useCase.validateScript(script)
        val errors = validations.filter { it.severity == ScriptValidationSeverity.ERROR }
        assertThat(errors).hasSize(1)
        assertThat(errors[0].message).contains("at least one step")
    }

    @Test
    @DisplayName("validateScript with CONNECT before READ passes without error")
    fun testValidateScript_connectBeforeRead_ok() {
        val script = TestScript(
            name = "valid",
            steps = listOf(
                ScriptStep(type = ScriptStepType.CONNECT, params = mapOf("address" to "AA:BB:CC:DD:EE:FF")),
                ScriptStep(type = ScriptStepType.READ, params = mapOf("service" to "s1", "characteristic" to "c1"))
            )
        )
        val validations = useCase.validateScript(script)
        val errors = validations.filter { it.severity == ScriptValidationSeverity.ERROR }
        assertThat(errors).isEmpty()
    }

    @Test
    @DisplayName("validateScript with READ without CONNECT returns ERROR")
    fun testValidateScript_readWithoutConnect_error() {
        val script = TestScript(
            name = "no-connect",
            steps = listOf(
                ScriptStep(type = ScriptStepType.READ, params = mapOf("service" to "s1", "characteristic" to "c1"))
            )
        )
        val validations = useCase.validateScript(script)
        val errors = validations.filter { it.severity == ScriptValidationSeverity.ERROR }
        assertThat(errors).isNotEmpty()
        assertThat(errors.any { it.message.contains("requires a prior CONNECT") }).isTrue()
    }

    @Test
    @DisplayName("validateScript with LOOP exceeding 1000 iterations returns WARNING")
    fun testValidateScript_loopNoMax_warning() {
        val script = TestScript(
            name = "big-loop",
            steps = listOf(
                ScriptStep(type = ScriptStepType.LOOP, params = mapOf("maxIterations" to "5000"))
            )
        )
        val validations = useCase.validateScript(script)
        val warnings = validations.filter { it.severity == ScriptValidationSeverity.WARNING }
        assertThat(warnings).isNotEmpty()
        assertThat(warnings.any { it.message.contains("5000") }).isTrue()
    }

    @Test
    @DisplayName("validateScript with undefined variable reference returns ERROR")
    fun testValidateScript_undefinedVariable_error() {
        val script = TestScript(
            name = "bad-var",
            steps = listOf(
                ScriptStep(
                    type = ScriptStepType.WRITE,
                    params = mapOf("value" to "\${undefinedVar}"),
                    onError = ErrorAction.STOP
                )
            )
        )
        val validations = useCase.validateScript(script)
        val errors = validations.filter { it.severity == ScriptValidationSeverity.ERROR }
        assertThat(errors.any { it.message.contains("Undefined variable") }).isTrue()
    }

    @Test
    @DisplayName("validateScript without DISCONNECT returns INFO")
    fun testValidateScript_disconnectAtEnd_info() {
        val script = TestScript(
            name = "no-disconnect",
            steps = listOf(
                ScriptStep(type = ScriptStepType.SCAN)
            )
        )
        val validations = useCase.validateScript(script)
        val infos = validations.filter { it.severity == ScriptValidationSeverity.INFO }
        assertThat(infos.any { it.message.contains("DISCONNECT") }).isTrue()
    }

    @Test
    @DisplayName("validateScript with fully valid script returns no errors")
    fun testValidateScript_validScript_noErrors() {
        val script = TestScript(
            name = "valid-script",
            steps = listOf(
                ScriptStep(type = ScriptStepType.SCAN, params = mapOf("duration" to "3000")),
                ScriptStep(type = ScriptStepType.CONNECT, params = mapOf("address" to "AA:BB:CC:DD:EE:FF")),
                ScriptStep(
                    type = ScriptStepType.READ,
                    params = mapOf("service" to "s1", "characteristic" to "c1")
                ),
                ScriptStep(type = ScriptStepType.DISCONNECT)
            ),
            variables = listOf(ScriptVariable(name = "myVar", value = "42"))
        )
        val validations = useCase.validateScript(script)
        val errors = validations.filter { it.severity == ScriptValidationSeverity.ERROR }
        assertThat(errors).isEmpty()
    }

    // ── Variable resolution tests ──

    @Test
    @DisplayName("resolveVariable replaces existing variable placeholder")
    fun testResolveVariable_existing() {
        val result = useCase.resolveVariable("value is \${count}", mapOf("count" to "42"))
        assertThat(result).isEqualTo("value is 42")
    }

    @Test
    @DisplayName("resolveVariable leaves missing variable placeholder unchanged")
    fun testResolveVariable_missing() {
        val result = useCase.resolveVariable("value is \${missing}", emptyMap())
        assertThat(result).isEqualTo("value is \${missing}")
    }

    @Test
    @DisplayName("resolveVariable resolves multiple variables in one string")
    fun testResolveVariable_nested() {
        val result = useCase.resolveVariable(
            "\${a} and \${b}",
            mapOf("a" to "hello", "b" to "world")
        )
        assertThat(result).isEqualTo("hello and world")
    }

    // ── Step creation test ──

    @Test
    @DisplayName("createStep produces step with correct type and params")
    fun testCreateStep_correctType() {
        val params = mapOf("address" to "AA:BB:CC:DD:EE:FF")
        val step = useCase.createStep(ScriptStepType.CONNECT, params)
        assertThat(step.type).isEqualTo(ScriptStepType.CONNECT)
        assertThat(step.params).isEqualTo(params)
        assertThat(step.onError).isEqualTo(ErrorAction.STOP)
    }

    // ── Duration estimation test ──

    @Test
    @DisplayName("estimateDuration sums step timeouts and wait durations")
    fun testEstimateDuration_sumTimeouts() {
        val script = TestScript(
            name = "timed",
            steps = listOf(
                ScriptStep(type = ScriptStepType.SCAN, timeout = 5000),
                ScriptStep(type = ScriptStepType.WAIT, params = mapOf("duration" to "2000"), timeout = 3000),
                ScriptStep(type = ScriptStepType.CONNECT, timeout = 10000)
            )
        )
        val duration = useCase.estimateDuration(script)
        // 5000 + 3000 + 2000 (wait) + 10000 = 20000
        assertThat(duration).isEqualTo(20000L)
    }

    // ── Templates test ──

    @Test
    @DisplayName("getStepTemplates returns one template per ScriptStepType")
    fun testGetStepTemplates_allTypesCovered() {
        val templates = useCase.getStepTemplates()
        assertThat(templates).hasSize(ScriptStepType.entries.size)
        val types = templates.map { it.type }.toSet()
        assertThat(types).containsExactlyElementsIn(ScriptStepType.entries)
    }

    // ── JSON serialization tests ──

    @Test
    @DisplayName("parseScriptFromJson deserializes valid JSON into TestScript")
    fun testParseScriptFromJson_valid() {
        val json = """{"name":"test","description":"desc","steps":[{"type":"SCAN","params":{"duration":"3000"}}]}"""
        val script = useCase.parseScriptFromJson(json)
        assertThat(script).isNotNull()
        assertThat(script!!.name).isEqualTo("test")
        assertThat(script.steps).hasSize(1)
        assertThat(script.steps[0].type).isEqualTo(ScriptStepType.SCAN)
    }

    @Test
    @DisplayName("serializeScriptToJson produces valid JSON string")
    fun testSerializeScriptToJson_valid() {
        val script = TestScript(
            name = "json-test",
            description = "serialization test",
            steps = listOf(ScriptStep(type = ScriptStepType.SCAN))
        )
        val json = useCase.serializeScriptToJson(script)
        assertThat(json).contains("json-test")
        assertThat(json).contains("SCAN")
    }

    @Test
    @DisplayName("JSON round-trip preserves script data")
    fun testSerializeRoundTrip() {
        val original = TestScript(
            name = "roundtrip",
            description = "round trip test",
            author = "tester",
            version = 2,
            targetDevice = "AA:BB:CC:DD:EE:FF",
            steps = listOf(
                ScriptStep(type = ScriptStepType.CONNECT, params = mapOf("address" to "AA:BB:CC:DD:EE:FF")),
                ScriptStep(
                    type = ScriptStepType.WRITE,
                    params = mapOf("service" to "s1", "characteristic" to "c1", "value" to "0x01"),
                    label = "write-step",
                    onError = ErrorAction.RETRY,
                    timeout = 15000
                ),
                ScriptStep(type = ScriptStepType.DISCONNECT)
            ),
            variables = listOf(
                ScriptVariable(name = "count", value = "10", type = VariableType.INTEGER)
            ),
            timeout = 120000,
            tags = listOf("ble", "security")
        )
        val json = useCase.serializeScriptToJson(original)
        val restored = useCase.parseScriptFromJson(json)

        assertThat(restored).isNotNull()
        assertThat(restored!!.name).isEqualTo(original.name)
        assertThat(restored.description).isEqualTo(original.description)
        assertThat(restored.author).isEqualTo(original.author)
        assertThat(restored.version).isEqualTo(original.version)
        assertThat(restored.steps).hasSize(original.steps.size)
        assertThat(restored.steps[1].label).isEqualTo("write-step")
        assertThat(restored.steps[1].onError).isEqualTo(ErrorAction.RETRY)
        assertThat(restored.steps[1].timeout).isEqualTo(15000)
        assertThat(restored.variables).hasSize(1)
        assertThat(restored.variables[0].type).isEqualTo(VariableType.INTEGER)
        assertThat(restored.tags).containsExactly("ble", "security")
    }

    @Test
    @DisplayName("validateScript with LOOP without maxIterations returns ERROR")
    fun testValidateScript_loopWithoutBound_error() {
        val script = TestScript(
            name = "infinite-loop",
            steps = listOf(
                ScriptStep(type = ScriptStepType.LOOP, params = mapOf("startIndex" to "0"))
            )
        )
        val validations = useCase.validateScript(script)
        val errors = validations.filter { it.severity == ScriptValidationSeverity.ERROR }
        assertThat(errors.any { it.message.contains("no maxIterations") }).isTrue()
    }

    @Test
    @DisplayName("validateScript with ASSERT missing expected returns ERROR")
    fun testValidateScript_assertMissingExpected_error() {
        val script = TestScript(
            name = "bad-assert",
            steps = listOf(
                ScriptStep(type = ScriptStepType.ASSERT, params = mapOf("field" to "status"))
            )
        )
        val validations = useCase.validateScript(script)
        val errors = validations.filter { it.severity == ScriptValidationSeverity.ERROR }
        assertThat(errors.any { it.message.contains("missing") }).isTrue()
    }

    @Test
    @DisplayName("parseScriptFromJson returns null for invalid JSON")
    fun testParseScriptFromJson_invalid() {
        val result = useCase.parseScriptFromJson("not valid json {{{")
        assertThat(result).isNull()
    }
}
