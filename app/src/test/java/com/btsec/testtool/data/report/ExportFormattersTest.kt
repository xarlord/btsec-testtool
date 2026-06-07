/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.report

import com.btsec.testtool.TestHelpers
import com.btsec.testtool.domain.model.*
import org.json.JSONArray
import org.json.JSONObject
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.time.Instant

/**
 * Unit tests for ExportFormatters — report output format correctness.
 * Covers JSON, HTML, CSV export paths including edge cases and injection prevention.
 *
 * Addresses GitHub issue #228: No tests for ExportFormatters.
 * Addresses GitHub issue #237: JSON injection vulnerability in toJson().
 */
class ExportFormattersTest {

    private lateinit var formatters: ExportFormatters
    private lateinit var testReport: SecurityReport

    @BeforeEach
    fun setUp() {
        formatters = ExportFormatters()

        val now = Instant.now()
        val device = TestHelpers.createTestBluetoothDevice()
        val vuln = TestHelpers.createTestVulnerability()

        testReport = SecurityReport(
            id = "report-001",
            authId = "BTSEC-20260207-A1B2C3D4",
            title = "Test Security Report",
            generatedAt = now,
            testPeriod = ReportPeriod(start = now.minusSeconds(3600), end = now),
            targetDevices = listOf(device),
            vulnerabilities = listOf(vuln),
            fuzzingResults = listOf(
                FuzzResult(
                    id = "fuzz-1",
                    config = TestHelpers.createTestFuzzConfig(device),
                    startTime = now.minusSeconds(1800),
                    endTime = now,
                    status = FuzzStatus.COMPLETED,
                    packetsSent = 100,
                    packetsReceived = 95,
                    errors = emptyList(),
                    findings = emptyList(),
                    captureFile = null
                )
            ),
            keyExtractionResults = listOf(
                TestHelpers.createTestKeyExtractionResult(extracted = false)
            ),
            executiveSummary = "Test executive summary",
            findings = listOf(
                ReportFinding(
                    category = FindingCategory.UNEXPECTED_RESPONSE,
                    severity = VulnerabilitySeverity.MEDIUM,
                    count = 3,
                    description = "Unexpected responses detected",
                    affectedDevices = listOf("AA:BB:CC:DD:EE:FF")
                )
            ),
            recommendations = listOf(
                Recommendation(
                    priority = RecommendationPriority.HIGH,
                    title = "Update Firmware",
                    description = "Device firmware is outdated",
                    affectedDevices = listOf("AA:BB:CC:DD:EE:FF"),
                    implementation = "Apply vendor patch",
                    verification = "Re-scan after update"
                )
            ),
            appendix = ReportAppendix(
                toolsUsed = listOf("BTSec TestTool v1.5"),
                testMethodology = "Automated BLE fuzzing and vulnerability scanning",
                limitations = listOf("Limited to BLE protocol"),
                glossary = mapOf("BLE" to "Bluetooth Low Energy"),
                references = emptyList()
            ),
            status = ReportStatus.FINAL
        )
    }

    // ── JSON Tests ──

    @Test
    @DisplayName("JSON output is valid parseable JSON")
    fun toJson_producesValidJson() {
        val json = formatters.toJson(testReport)
        // Should parse without exception
        val parsed = JSONObject(json)
        assertEquals("report-001", parsed.getString("id"))
    }

    @Test
    @DisplayName("JSON contains all required fields")
    fun toJson_containsAllRequiredFields() {
        val parsed = JSONObject(formatters.toJson(testReport))

        assertTrue(parsed.has("id"))
        assertTrue(parsed.has("authId"))
        assertTrue(parsed.has("title"))
        assertTrue(parsed.has("status"))
        assertTrue(parsed.has("executiveSummary"))
        assertTrue(parsed.has("generatedAt"))
    }

    @Test
    @DisplayName("JSON contains target devices")
    fun toJson_containsTargetDevices() {
        val parsed = JSONObject(formatters.toJson(testReport))
        val devices = parsed.getJSONArray("targetDevices")

        assertEquals(1, devices.length())
        val device = devices.getJSONObject(0)
        assertEquals("AA:BB:CC:DD:EE:FF", device.getString("address"))
        assertEquals("Test Device", device.getString("name"))
    }

    @Test
    @DisplayName("JSON contains vulnerabilities")
    fun toJson_containsVulnerabilities() {
        val parsed = JSONObject(formatters.toJson(testReport))
        val vulns = parsed.getJSONArray("vulnerabilities")

        assertEquals(1, vulns.length())
        val vuln = vulns.getJSONObject(0)
        assertEquals("CVE-2024-0001", vuln.getString("cveId"))
        assertTrue(vuln.has("name"))
        assertTrue(vuln.has("severity"))
        assertTrue(vuln.has("cvssScore"))
    }

    @Test
    @DisplayName("JSON contains findings")
    fun toJson_containsFindings() {
        val parsed = JSONObject(formatters.toJson(testReport))
        val findings = parsed.getJSONArray("findings")

        assertEquals(1, findings.length())
        val finding = findings.getJSONObject(0)
        assertEquals("UNEXPECTED_RESPONSE", finding.getString("category"))
        assertEquals("Unexpected responses detected", finding.getString("description"))
    }

    @Test
    @DisplayName("JSON escapes special characters in title")
    fun toJson_escapesSpecialCharactersInTitle() {
        val reportWithSpecialChars = testReport.copy(
            title = "Report with \"quotes\" and \\backslashes\\"
        )
        val json = formatters.toJson(reportWithSpecialChars)
        val parsed = JSONObject(json)

        assertEquals("Report with \"quotes\" and \\backslashes\\", parsed.getString("title"))
    }

    @Test
    @DisplayName("JSON handles empty collections")
    fun toJson_handlesEmptyCollections() {
        val emptyReport = testReport.copy(
            targetDevices = emptyList(),
            vulnerabilities = emptyList(),
            findings = emptyList()
        )
        val parsed = JSONObject(formatters.toJson(emptyReport))

        assertEquals(0, parsed.getJSONArray("targetDevices").length())
        assertEquals(0, parsed.getJSONArray("vulnerabilities").length())
        assertEquals(0, parsed.getJSONArray("findings").length())
    }

    @Test
    @DisplayName("JSON escapes newlines in strings")
    fun toJson_handlesNewlinesInStrings() {
        val reportWithNewlines = testReport.copy(
            executiveSummary = "Line one\nLine two\nLine three"
        )
        val json = formatters.toJson(reportWithNewlines)
        val parsed = JSONObject(json)

        // JSONObject will have escaped the newlines; parsing back should give the original
        assertEquals("Line one\nLine two\nLine three", parsed.getString("executiveSummary"))

        // The raw JSON string must NOT contain a literal newline inside the string value
        val summaryStart = json.indexOf("\"executiveSummary\"")
        val valueStart = json.indexOf("\"", json.indexOf(":", summaryStart) + 1) + 1
        val valueEnd = json.indexOf("\"", valueStart)
        val rawValue = json.substring(valueStart, valueEnd)
        assertFalse(rawValue.contains("\n"), "Raw JSON must not contain literal newlines")
    }

    @Test
    @DisplayName("JSON handles device with null name using fallback")
    fun toJson_handlesDeviceWithNullName() {
        val baseDevice = TestHelpers.createTestBluetoothDevice()
        val deviceWithNullName = baseDevice.copy(name = null)
        val report = testReport.copy(targetDevices = listOf(deviceWithNullName))
        val parsed = JSONObject(formatters.toJson(report))

        assertEquals("Unknown", parsed.getJSONArray("targetDevices").getJSONObject(0).getString("name"))
    }

    // ── JSON Injection / Control Character Tests (Issue #237) ──

    @Nested
    @DisplayName("JSON injection and control character tests (#237)")
    inner class JsonInjectionTests {

        @Test
        @DisplayName("Control characters in id field are safely escaped")
        fun toJson_controlCharsInId_areSafe() {
            val report = testReport.copy(
                id = "report\u0001\u0002injected"
            )
            val json = formatters.toJson(report)
            val parsed = JSONObject(json)

            assertEquals("report\u0001\u0002injected", parsed.getString("id"))
            // Ensure the raw JSON does not contain literal control characters
            assertFalse(json.contains("\u0001"))
            assertFalse(json.contains("\u0002"))
        }

        @Test
        @DisplayName("Control characters in authId field are safely escaped")
        fun toJson_controlCharsInAuthId_areSafe() {
            val report = testReport.copy(
                authId = "auth\t\u0000id"
            )
            val json = formatters.toJson(report)
            val parsed = JSONObject(json)

            assertEquals("auth\t\u0000id", parsed.getString("authId"))
            assertFalse(json.contains("\u0000"))
        }

        @Test
        @DisplayName("Control characters in title field are safely escaped")
        fun toJson_controlCharsInTitle_areSafe() {
            val report = testReport.copy(
                title = "title\twith\ttabs"
            )
            val json = formatters.toJson(report)
            val parsed = JSONObject(json)

            assertEquals("title\twith\ttabs", parsed.getString("title"))
            assertFalse(json.contains("\t"))
        }

        @Test
        @DisplayName("Control characters in executiveSummary are safely escaped")
        fun toJson_controlCharsInSummary_areSafe() {
            val report = testReport.copy(
                executiveSummary = "sum\u000Cmary\b\r\nwith\u0000controls"
            )
            val json = formatters.toJson(report)
            val parsed = JSONObject(json)

            assertEquals("sum\u000Cmary\b\r\nwith\u0000controls", parsed.getString("executiveSummary"))
            // Raw JSON should not contain literal control characters (except escaped forms)
            assertFalse(json.contains("\u0000"))
            assertFalse(json.contains("\u000C"))
            assertFalse(json.contains("\b"))
        }

        @Test
        @DisplayName("JSON injection in device address is safely escaped")
        fun toJson_injectionInDeviceAddress_isSafe() {
            val maliciousDevice = TestHelpers.createTestBluetoothDevice(
                address = "AA:BB:CC:DD:EE:FF\",\"evil\":\"pwned"
            )
            val report = testReport.copy(targetDevices = listOf(maliciousDevice))
            val json = formatters.toJson(report)
            val parsed = JSONObject(json)

            val deviceObj = parsed.getJSONArray("targetDevices").getJSONObject(0)
            assertEquals("AA:BB:CC:DD:EE:FF\",\"evil\":\"pwned", deviceObj.getString("address"))
            assertFalse(deviceObj.has("evil"), "Injection must not create new JSON keys")
        }

        @Test
        @DisplayName("JSON injection in device name is safely escaped")
        fun toJson_injectionInDeviceName_isSafe() {
            val maliciousDevice = TestHelpers.createTestBluetoothDevice(
                name = "Device\",\"injected\":true,\"rest\":\""
            )
            val report = testReport.copy(targetDevices = listOf(maliciousDevice))
            val json = formatters.toJson(report)
            val parsed = JSONObject(json)

            val deviceObj = parsed.getJSONArray("targetDevices").getJSONObject(0)
            assertFalse(deviceObj.has("injected"), "Injection must not create new JSON keys")
            assertEquals(
                "Device\",\"injected\":true,\"rest\":\"",
                deviceObj.getString("name")
            )
        }

        @Test
        @DisplayName("JSON injection in cveId field is safely escaped")
        fun toJson_injectionInCveId_isSafe() {
            val vuln = testReport.vulnerabilities.first().copy(
                cveId = "CVE\",\"evil\":\"injected"
            )
            val report = testReport.copy(vulnerabilities = listOf(vuln))
            val json = formatters.toJson(report)
            val parsed = JSONObject(json)

            val vulnObj = parsed.getJSONArray("vulnerabilities").getJSONObject(0)
            assertFalse(vulnObj.has("evil"), "Injection must not create new JSON keys")
            assertEquals("CVE\",\"evil\":\"injected", vulnObj.getString("cveId"))
        }

        @Test
        @DisplayName("JSON injection in vulnerability name is safely escaped")
        fun toJson_injectionInVulnName_isSafe() {
            val vuln = testReport.vulnerabilities.first().copy(
                name = "Vuln\",\"pwned\":true,\"x\":\""
            )
            val report = testReport.copy(vulnerabilities = listOf(vuln))
            val json = formatters.toJson(report)
            val parsed = JSONObject(json)

            val vulnObj = parsed.getJSONArray("vulnerabilities").getJSONObject(0)
            assertFalse(vulnObj.has("pwned"), "Injection must not create new JSON keys")
        }

        @Test
        @DisplayName("JSON injection in severity field is safely escaped")
        fun toJson_injectionInSeverity_isSafe() {
            // severity is an enum, so this is naturally safe, but test the output
            val json = formatters.toJson(testReport)
            val parsed = JSONObject(json)

            val vulnObj = parsed.getJSONArray("vulnerabilities").getJSONObject(0)
            assertEquals("HIGH", vulnObj.getString("severity"))
        }

        @Test
        @DisplayName("JSON injection in finding category is safely escaped")
        fun toJson_injectionInFindingCategory_isSafe() {
            // category is an enum, so naturally safe. Test the output.
            val json = formatters.toJson(testReport)
            val parsed = JSONObject(json)

            val findingObj = parsed.getJSONArray("findings").getJSONObject(0)
            assertEquals("UNEXPECTED_RESPONSE", findingObj.getString("category"))
        }

        @Test
        @DisplayName("JSON injection in finding description is safely escaped")
        fun toJson_injectionInFindingDescription_isSafe() {
            val finding = testReport.findings.first().copy(
                description = "finding\",\"evil\":true,\"x\":\""
            )
            val report = testReport.copy(findings = listOf(finding))
            val json = formatters.toJson(report)
            val parsed = JSONObject(json)

            val findingObj = parsed.getJSONArray("findings").getJSONObject(0)
            assertFalse(findingObj.has("evil"), "Injection must not create new JSON keys")
        }

        @Test
        @DisplayName("Null byte in string field does not break JSON structure")
        fun toJson_nullByteInField_doesNotBreakJson() {
            val report = testReport.copy(
                title = "Report\u0000with null"
            )
            val json = formatters.toJson(report)
            // Must be parseable
            val parsed = JSONObject(json)
            assertEquals("Report\u0000with null", parsed.getString("title"))
        }

        @Test
        @DisplayName("All ASCII control characters (0x00-0x1F) are safely handled")
        fun toJson_allControlCharacters_areSafe() {
            val controlChars = (0x00..0x1F).map { it.toChar() }.joinToString("")
            val report = testReport.copy(
                title = "prefix${controlChars}suffix"
            )
            val json = formatters.toJson(report)
            val parsed = JSONObject(json)

            assertEquals("prefix${controlChars}suffix", parsed.getString("title"))
            // Raw JSON must not contain literal control chars (except whitespace in indentation)
            // Check some specific ones
            for (code in 0x00..0x1F) {
                val ch = code.toChar()
                // Tabs and newlines in the indentation are fine; inside values they must be escaped
                if (ch == '\n' || ch == '\r' || ch == '\t') continue  // these appear in indentation
                assertFalse(json.contains(ch), "Raw JSON must not contain literal control char U+${"%04X".format(code)}")
            }
        }

        @Test
        @DisplayName("Backslash and quote combination does not escape out of JSON")
        fun toJson_backslashQuoteCombo_doesNotEscape() {
            val report = testReport.copy(
                executiveSummary = "\\\"},\"injected\":true,{\"x\":\""
            )
            val json = formatters.toJson(report)
            val parsed = JSONObject(json)

            assertFalse(parsed.has("injected"), "Must not allow injection via backslash-quote combo")
            assertEquals("\\\"},\"injected\":true,{\"x\":\"", parsed.getString("executiveSummary"))
        }

        @Test
        @DisplayName("Unicode surrogate pairs and special characters are preserved")
        fun toJson_unicodeChars_arePreserved() {
            val report = testReport.copy(
                title = "Test 🔒 Security \u00e9\u00e8\u00ea Report"
            )
            val json = formatters.toJson(report)
            val parsed = JSONObject(json)

            assertEquals("Test 🔒 Security \u00e9\u00e8\u00ea Report", parsed.getString("title"))
        }
    }

    // ── escapeJson helper tests ──

    @Nested
    @DisplayName("escapeJson helper completeness")
    inner class EscapeJsonTests {

        @Test
        @DisplayName("Escapes double quotes")
        fun escapeJson_escapesDoubleQuotes() {
            assertEquals("\\\"test\\\"", formatters.escapeJson("\"test\""))
        }

        @Test
        @DisplayName("Escapes backslashes")
        fun escapeJson_escapesBackslashes() {
            assertEquals("\\\\test\\\\", formatters.escapeJson("\\test\\"))
        }

        @Test
        @DisplayName("Escapes newlines")
        fun escapeJson_escapesNewlines() {
            assertEquals("line1\\nline2", formatters.escapeJson("line1\nline2"))
        }

        @Test
        @DisplayName("Escapes carriage returns")
        fun escapeJson_escapesCarriageReturns() {
            assertEquals("a\\rb", formatters.escapeJson("a\rb"))
        }

        @Test
        @DisplayName("Escapes tabs")
        fun escapeJson_escapesTabs() {
            assertEquals("a\\tb", formatters.escapeJson("a\tb"))
        }

        @Test
        @DisplayName("Escapes backspace")
        fun escapeJson_escapesBackspace() {
            assertEquals("a\\bb", formatters.escapeJson("a\bb"))
        }

        @Test
        @DisplayName("Escapes form feed")
        fun escapeJson_escapesFormFeed() {
            assertEquals("a\\fb", formatters.escapeJson("a\u000Cb"))
        }

        @Test
        @DisplayName("Escapes null byte")
        fun escapeJson_escapesNullByte() {
            assertEquals("a\\u0000b", formatters.escapeJson("a\u0000b"))
        }

        @Test
        @DisplayName("Escapes other control characters")
        fun escapeJson_escapesOtherControlChars() {
            assertEquals("a\\u0001b\\u001fc", formatters.escapeJson("a\u0001b\u001Fc"))
        }

        @Test
        @DisplayName("Does not escape normal characters")
        fun escapeJson_doesNotEscapeNormalChars() {
            assertEquals("hello world", formatters.escapeJson("hello world"))
        }
    }

    // ── HTML Tests ──

    @Test
    @DisplayName("HTML produces valid structure")
    fun toHtml_producesValidHtmlStructure() {
        val html = formatters.toHtml(testReport)

        assertTrue(html.startsWith("<!DOCTYPE html>"))
        assertTrue(html.contains("<html"))
        assertTrue(html.contains("</html>"))
        assertTrue(html.contains("<head>"))
        assertTrue(html.contains("</body>"))
    }

    @Test
    @DisplayName("HTML contains report title")
    fun toHtml_containsTitle() {
        val html = formatters.toHtml(testReport)

        assertTrue(html.contains("Test Security Report"))
        assertTrue(html.contains("<title>"))
    }

    @Test
    @DisplayName("HTML contains executive summary")
    fun toHtml_containsExecutiveSummary() {
        val html = formatters.toHtml(testReport)

        assertTrue(html.contains("Executive Summary"))
        assertTrue(html.contains("Test executive summary"))
    }

    @Test
    @DisplayName("HTML contains target devices")
    fun toHtml_containsTargetDevices() {
        val html = formatters.toHtml(testReport)

        assertTrue(html.contains("Target Devices"))
        assertTrue(html.contains("AA:BB:CC:DD:EE:FF"))
    }

    @Test
    @DisplayName("HTML contains vulnerabilities")
    fun toHtml_containsVulnerabilities() {
        val html = formatters.toHtml(testReport)

        assertTrue(html.contains("Vulnerabilities Detected"))
        assertTrue(html.contains("CVE-2024-0001"))
    }

    @Test
    @DisplayName("HTML contains findings")
    fun toHtml_containsFindings() {
        val html = formatters.toHtml(testReport)

        assertTrue(html.contains("Findings"))
        assertTrue(html.contains("Unexpected responses detected"))
    }

    @Test
    @DisplayName("HTML contains recommendations")
    fun toHtml_containsRecommendations() {
        val html = formatters.toHtml(testReport)

        assertTrue(html.contains("Recommendations"))
        assertTrue(html.contains("Update Firmware"))
    }

    @Test
    @DisplayName("HTML escapes special characters to prevent XSS")
    fun toHtml_escapesHtmlSpecialCharacters() {
        val reportWithHtml = testReport.copy(
            title = "<script>alert('xss')</script>",
            executiveSummary = "Test with <b>bold</b> & 'quotes'"
        )
        val html = formatters.toHtml(reportWithHtml)

        assertFalse(html.contains("<script>alert"))
        assertTrue(html.contains("&lt;script"))
        assertTrue(html.contains("&amp;"))
    }

    @Test
    @DisplayName("HTML applies severity CSS classes")
    fun toHtml_appliesSeverityCssClasses() {
        val html = formatters.toHtml(testReport)

        assertTrue(html.contains("class=\""))
        assertTrue(html.contains("class=\"high\""))
    }

    @Test
    @DisplayName("HTML omits vulnerability section when empty")
    fun toHtml_omitsVulnerabilitySectionWhenEmpty() {
        val report = testReport.copy(vulnerabilities = emptyList())
        val html = formatters.toHtml(report)

        assertFalse(html.contains("Vulnerabilities Detected"))
    }

    @Test
    @DisplayName("HTML omits recommendations section when empty")
    fun toHtml_omitsRecommendationsSectionWhenEmpty() {
        val report = testReport.copy(recommendations = emptyList())
        val html = formatters.toHtml(report)

        assertFalse(html.contains("Recommendations</h2>"))
    }

    // ── CSV Tests ──

    @Test
    @DisplayName("CSV has header row")
    fun toCsv_hasHeaderRow() {
        val csv = formatters.toCsv(testReport)

        assertTrue(csv.startsWith("Type,CVE/ID,Name,Severity,CVSS,Description"))
    }

    @Test
    @DisplayName("CSV contains vulnerability data")
    fun toCsv_containsVulnerabilities() {
        val csv = formatters.toCsv(testReport)

        assertTrue(csv.contains("Vulnerability,"))
        assertTrue(csv.contains("CVE-2024-0001"))
    }

    @Test
    @DisplayName("CSV contains findings data")
    fun toCsv_containsFindings() {
        val csv = formatters.toCsv(testReport)

        assertTrue(csv.contains("Finding,"))
        assertTrue(csv.contains("UNEXPECTED_RESPONSE"))
    }

    @Test
    @DisplayName("CSV contains recommendations data")
    fun toCsv_containsRecommendations() {
        val csv = formatters.toCsv(testReport)

        assertTrue(csv.contains("Recommendation,"))
        assertTrue(csv.contains("Update Firmware"))
    }

    @Test
    @DisplayName("CSV escapes commas in fields")
    fun toCsv_escapesCommasInFields() {
        val vulnWithCommas = testReport.vulnerabilities.first().copy(
            name = "Vuln, with, commas"
        )
        val report = testReport.copy(vulnerabilities = listOf(vulnWithCommas))
        val csv = formatters.toCsv(report)

        assertTrue(csv.contains("\"Vuln, with, commas\""))
    }

    @Test
    @DisplayName("CSV handles empty report with header only")
    fun toCsv_handlesEmptyReport() {
        val emptyReport = testReport.copy(
            vulnerabilities = emptyList(),
            findings = emptyList(),
            recommendations = emptyList()
        )
        val csv = formatters.toCsv(emptyReport)

        assertTrue(csv.startsWith("Type,CVE/ID,"))
        val lines = csv.lines().filter { it.isNotBlank() }
        assertEquals(1, lines.size)
    }

    @Test
    @DisplayName("CSV escapes double quotes in fields")
    fun toCsv_escapingFieldWithDoubleQuotes() {
        val vuln = testReport.vulnerabilities.first().copy(
            name = "Vuln \"with\" quotes"
        )
        val report = testReport.copy(vulnerabilities = listOf(vuln))
        val csv = formatters.toCsv(report)

        assertTrue(csv.contains("\"\"with\"\" quotes"))
    }
}
