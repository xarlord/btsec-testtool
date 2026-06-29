/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.fuzzing

import com.btsec.testtool.domain.model.FuzzingCategory
import com.btsec.testtool.domain.model.FuzzingSeverity
import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

/**
 * Unit tests for [HfpFuzzingPatterns].
 *
 * Verifies that HFP AT-command injection fuzzing patterns are well-formed,
 * correctly categorized, and reference known CVEs where applicable.
 */
@DisplayName("HfpFuzzingPatterns")
class HfpFuzzingPatternsTest {
    @Test
    fun `allPatterns returns non-empty list`() {
        val patterns = HfpFuzzingPatterns.allPatterns()
        assertThat(patterns).isNotEmpty()
    }

    @Test
    fun `every pattern has unique id`() {
        val patterns = HfpFuzzingPatterns.allPatterns()
        val ids = patterns.map { it.id }
        assertThat(ids).hasSize(ids.toSet().size)
    }

    @Test
    fun `every pattern has at least one payload`() {
        val patterns = HfpFuzzingPatterns.allPatterns()
        for (p in patterns) {
            assertThat(p.payloads).isNotEmpty()
        }
    }

    @Test
    fun `format string patterns reference CVE-2020-16142`() {
        val fmt = HfpFuzzingPatterns.formatStringPatterns
        assertThat(fmt).isNotEmpty()
        assertThat(fmt.all { it.cveReferences.contains("CVE-2020-16142") }).isTrue()
    }

    @Test
    fun `byCategory returns correct patterns`() {
        val inj = HfpFuzzingPatterns.byCategory(FuzzingCategory.COMMAND_INJECTION)
        assertThat(inj).isNotEmpty()
        assertThat(inj.all { it.category == FuzzingCategory.COMMAND_INJECTION }).isTrue()
    }

    @Test
    fun `bySeverity returns correct patterns`() {
        val critical = HfpFuzzingPatterns.bySeverity(FuzzingSeverity.CRITICAL)
        assertThat(critical).isNotEmpty()
        assertThat(critical.all { it.severity == FuzzingSeverity.CRITICAL }).isTrue()
    }

    @Test
    fun `withCveReferences returns only patterns with CVEs`() {
        val withCve = HfpFuzzingPatterns.withCveReferences()
        assertThat(withCve).isNotEmpty()
        assertThat(withCve.all { it.cveReferences.isNotEmpty() }).isTrue()
    }

    @Test
    fun `every category is represented in allPatterns`() {
        val patterns = HfpFuzzingPatterns.allPatterns()
        val categories = patterns.map { it.category }.toSet()
        assertThat(categories).containsAtLeast(
            FuzzingCategory.AT_INJECTION,
            FuzzingCategory.BUFFER_OVERFLOW,
            FuzzingCategory.COMMAND_INJECTION,
            FuzzingCategory.INTEGER_OVERFLOW,
            FuzzingCategory.HFP_COMMAND,
        )
    }

    @Test
    fun `every pattern has non-empty name and description`() {
        for (p in HfpFuzzingPatterns.allPatterns()) {
            assertThat(p.name).isNotEmpty()
            assertThat(p.description).isNotEmpty()
        }
    }
}
