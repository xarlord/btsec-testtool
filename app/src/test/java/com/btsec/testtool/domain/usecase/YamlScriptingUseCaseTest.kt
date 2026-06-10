/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

/**
 * Tests for [YamlScriptingUseCase].
 *
 * All test scenarios are designed for AUTHORIZED security testing validation.
 */
class YamlScriptingUseCaseTest {

    private lateinit var useCase: YamlScriptingUseCase

    @BeforeEach
    fun setup() {
        useCase = YamlScriptingUseCase()
    }

    @Nested
    @DisplayName("parseYaml")
    inner class ParseYaml {

        @Test
        @DisplayName("should parse a valid complete YAML script")
        fun testParseYaml_validScript() {
            val yaml = """
                name: "Heart Rate Monitor Test"
                description: "Tests BLE heart rate service"
                author: "Security Researcher"
                version: 2
                target: "AA:BB:CC:DD:EE:FF"
                timeout: 30000
                steps:
                  - action: scan
                    timeout: 5000
                  - action: connect
                    params:
                      address: "AA:BB:CC:DD:EE:FF"
                  - action: read
                    params:
                      service: "180D"
                      characteristic: "2A37"
                    label: "Read heart rate"
                  - action: disconnect
            """.trimIndent()

            val result = useCase.parseYaml(yaml)

            assertThat(result.errors).isEmpty()
            assertThat(result.script).isNotNull()
            val script = result.script!!
            assertThat(script.name).isEqualTo("Heart Rate Monitor Test")
            assertThat(script.description).isEqualTo("Tests BLE heart rate service")
            assertThat(script.author).isEqualTo("Security Researcher")
            assertThat(script.version).isEqualTo(2)
            assertThat(script.target).isEqualTo("AA:BB:CC:DD:EE:FF")
            assertThat(script.timeout).isEqualTo(30000L)
            assertThat(script.steps).hasSize(4)
            assertThat(script.steps[0].action).isEqualTo("scan")
            assertThat(script.steps[0].timeout).isEqualTo(5000L)
            assertThat(script.steps[1].action).isEqualTo("connect")
            assertThat(script.steps[1].params["address"]).isEqualTo("AA:BB:CC:DD:EE:FF")
            assertThat(script.steps[2].action).isEqualTo("read")
            assertThat(script.steps[2].params["service"]).isEqualTo("180D")
            assertThat(script.steps[2].params["characteristic"]).isEqualTo("2A37")
            assertThat(script.steps[2].label).isEqualTo("Read heart rate")
            assertThat(script.steps[3].action).isEqualTo("disconnect")
        }

        @Test
        @DisplayName("should return error for empty YAML string")
        fun testParseYaml_emptyString_error() {
            val result = useCase.parseYaml("")

            assertThat(result.errors).isNotEmpty()
            assertThat(result.script).isNull()
            assertThat(result.errors.any { it.message.contains("empty") }).isTrue()
        }

        @Test
        @DisplayName("should return warning when name is missing")
        fun testParseYaml_missingName_warning() {
            val yaml = """
                description: "No name script"
                steps:
                  - action: scan
            """.trimIndent()

            val result = useCase.parseYaml(yaml)

            assertThat(result.warnings).isNotEmpty()
            assertThat(result.warnings.any { it.message.contains("name") }).isTrue()
        }

        @Test
        @DisplayName("should return error when no steps are defined")
        fun testParseYaml_noSteps_error() {
            val yaml = """
                name: "No Steps Script"
                description: "Missing steps"
            """.trimIndent()

            val result = useCase.parseYaml(yaml)

            assertThat(result.errors).isNotEmpty()
            assertThat(result.errors.any { it.message.contains("no steps") }).isTrue()
            assertThat(result.script).isNull()
        }

        @Test
        @DisplayName("should parse variables block correctly")
        fun testParseYaml_withVariables() {
            val yaml = """
                name: "Variable Test"
                description: "Test with variables"
                variables:
                  service_uuid: "180D"
                  char_uuid: "2A37"
                  test_value: "0x01"
                steps:
                  - action: scan
            """.trimIndent()

            val result = useCase.parseYaml(yaml)

            assertThat(result.errors).isEmpty()
            assertThat(result.script).isNotNull()
            val vars = result.script!!.variables
            assertThat(vars["service_uuid"]).isEqualTo("180D")
            assertThat(vars["char_uuid"]).isEqualTo("2A37")
            assertThat(vars["test_value"]).isEqualTo("0x01")
        }

        @Test
        @DisplayName("should parse tags in flow style")
        fun testParseYaml_withTags() {
            val yaml = """
                name: "Tagged Test"
                description: "Test with tags"
                tags: [ble, security, heart_rate]
                steps:
                  - action: scan
            """.trimIndent()

            val result = useCase.parseYaml(yaml)

            assertThat(result.errors).isEmpty()
            assertThat(result.script).isNotNull()
            assertThat(result.script!!.tags).containsExactly("ble", "security", "heart_rate")
        }

        @Test
        @DisplayName("should parse nested params in steps")
        fun testParseYaml_nestedParams() {
            val yaml = """
                name: "Nested Params Test"
                description: "Test nested params"
                steps:
                  - action: write
                    params:
                      service: "180D"
                      characteristic: "2A39"
                      value: "0x0102"
                    label: "Write custom value"
                    timeout: 15000
                    repeat: 3
                    continue: retry
                  - action: disconnect
            """.trimIndent()

            val result = useCase.parseYaml(yaml)

            assertThat(result.errors).isEmpty()
            assertThat(result.script).isNotNull()
            val step = result.script!!.steps[0]
            assertThat(step.action).isEqualTo("write")
            assertThat(step.params).hasSize(3)
            assertThat(step.params["service"]).isEqualTo("180D")
            assertThat(step.params["characteristic"]).isEqualTo("2A39")
            assertThat(step.params["value"]).isEqualTo("0x0102")
            assertThat(step.label).isEqualTo("Write custom value")
            assertThat(step.timeout).isEqualTo(15000L)
            assertThat(step.repeat).isEqualTo(3)
            assertThat(step.`continue`).isEqualTo("retry")
        }
    }

    @Nested
    @DisplayName("validateYamlScript")
    inner class ValidateYamlScript {

        @Test
        @DisplayName("should return no errors for a valid script")
        fun testValidateYamlScript_valid_noErrors() {
            val script = createValidScript()

            val errors = useCase.validateYamlScript(script)

            assertThat(errors).isEmpty()
        }

        @Test
        @DisplayName("should return error for invalid action")
        fun testValidateYamlScript_invalidAction_error() {
            val script = createValidScript().copy(
                steps = listOf(
                    com.btsec.testtool.domain.model.YamlStep(action = "scan"),
                    com.btsec.testtool.domain.model.YamlStep(action = "invalid_action")
                )
            )

            val errors = useCase.validateYamlScript(script)

            assertThat(errors.any { it.message.contains("Invalid action") }).isTrue()
        }

        @Test
        @DisplayName("should return error for empty name")
        fun testValidateYamlScript_emptyName_error() {
            val script = createValidScript().copy(name = "")

            val errors = useCase.validateYamlScript(script)

            assertThat(errors.any { it.message.contains("name") && it.message.contains("empty") }).isTrue()
        }

        @Test
        @DisplayName("should allow read after connect")
        fun testValidateYamlScript_connectBeforeRead_ok() {
            val script = createValidScript().copy(
                steps = listOf(
                    com.btsec.testtool.domain.model.YamlStep(action = "scan"),
                    com.btsec.testtool.domain.model.YamlStep(action = "connect"),
                    com.btsec.testtool.domain.model.YamlStep(
                        action = "read",
                        params = mapOf("service" to "180D")
                    ),
                    com.btsec.testtool.domain.model.YamlStep(action = "disconnect")
                )
            )

            val errors = useCase.validateYamlScript(script)

            assertThat(errors.none { it.message.contains("no connect") }).isTrue()
        }

        @Test
        @DisplayName("should return error for read without prior connect")
        fun testValidateYamlScript_readWithoutConnect_error() {
            val script = createValidScript().copy(
                steps = listOf(
                    com.btsec.testtool.domain.model.YamlStep(action = "scan"),
                    com.btsec.testtool.domain.model.YamlStep(
                        action = "read",
                        params = mapOf("service" to "180D")
                    )
                )
            )

            val errors = useCase.validateYamlScript(script)

            assertThat(errors.any { it.message.contains("no connect step precedes") }).isTrue()
        }

        @Test
        @DisplayName("should return error for undefined variable references")
        fun testValidateYamlScript_undefinedVariable_error() {
            val script = createValidScript().copy(
                variables = mapOf("service_uuid" to "180D"),
                steps = listOf(
                    com.btsec.testtool.domain.model.YamlStep(action = "connect"),
                    com.btsec.testtool.domain.model.YamlStep(
                        action = "read",
                        params = mapOf(
                            "service" to "\${service_uuid}",
                            "characteristic" to "\${undefined_var}"
                        )
                    )
                )
            )

            val errors = useCase.validateYamlScript(script)

            assertThat(errors.any { it.message.contains("undefined variable") }).isTrue()
        }
    }

    @Nested
    @DisplayName("resolveVariables")
    inner class ResolveVariables {

        @Test
        @DisplayName("should replace existing variable references")
        fun testResolveVariables_existing() {
            val variables = mapOf(
                "service_uuid" to "180D",
                "char_uuid" to "2A37"
            )

            val result = useCase.resolveVariables("\${service_uuid}/\${char_uuid}", variables)

            assertThat(result).isEqualTo("180D/2A37")
        }

        @Test
        @DisplayName("should keep unresolved references intact")
        fun testResolveVariables_missing_keepsOriginal() {
            val variables = mapOf("service_uuid" to "180D")

            val result = useCase.resolveVariables("\${service_uuid}/\${unknown}", variables)

            assertThat(result).isEqualTo("180D/\${unknown}")
        }
    }

    @Nested
    @DisplayName("getYamlTemplate")
    inner class GetYamlTemplate {

        @Test
        @DisplayName("should return a non-empty template string")
        fun testGetYamlTemplate_notEmpty() {
            val template = useCase.getYamlTemplate()

            assertThat(template).isNotEmpty()
            assertThat(template).contains("name:")
            assertThat(template).contains("steps:")
            assertThat(template).contains("action:")
        }
    }

    @Nested
    @DisplayName("getYamlActionReference")
    inner class GetYamlActionReference {

        @Test
        @DisplayName("should contain all valid actions with descriptions")
        fun testGetYamlActionReference_hasAllActions() {
            val reference = useCase.getYamlActionReference()

            assertThat(reference).hasSize(13)
            assertThat(reference).containsKey("scan")
            assertThat(reference).containsKey("connect")
            assertThat(reference).containsKey("disconnect")
            assertThat(reference).containsKey("read")
            assertThat(reference).containsKey("write")
            assertThat(reference).containsKey("subscribe")
            assertThat(reference).containsKey("fuzz")
            assertThat(reference).containsKey("assert")
            assertThat(reference).containsKey("wait")
            assertThat(reference).containsKey("log")
            assertThat(reference).containsKey("service_discovery")
            assertThat(reference).containsKey("pair")
            assertThat(reference).containsKey("unpair")
            // Verify descriptions are meaningful
            for ((_, desc) in reference) {
                assertThat(desc).isNotEmpty()
            }
        }
    }

    private fun createValidScript(): com.btsec.testtool.domain.model.YamlTestScript {
        return com.btsec.testtool.domain.model.YamlTestScript(
            name = "Valid Test Script",
            description = "A valid test for AUTHORIZED security testing",
            steps = listOf(
                com.btsec.testtool.domain.model.YamlStep(action = "scan"),
                com.btsec.testtool.domain.model.YamlStep(action = "connect"),
                com.btsec.testtool.domain.model.YamlStep(
                    action = "read",
                    params = mapOf("service" to "180D")
                ),
                com.btsec.testtool.domain.model.YamlStep(action = "disconnect")
            )
        )
    }
}
