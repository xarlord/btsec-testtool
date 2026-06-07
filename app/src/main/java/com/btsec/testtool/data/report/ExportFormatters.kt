/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.report

import com.btsec.testtool.domain.model.*
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Export formatters for security reports.
 * Supports JSON, HTML, CSV output formats.
 */
@Singleton
class ExportFormatters @Inject constructor() {

    private val dateFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US)

    /**
     * Export report as JSON string.
     *
     * Uses JSONObject/JSONArray to build the output, ensuring all string values
     * are properly escaped (control characters, special chars, etc.) and
     * eliminating any risk of JSON injection via malformed field values.
     */
    fun toJson(report: SecurityReport): String {
        val root = JSONObject()
        root.put("id", report.id)
        root.put("authId", report.authId)
        root.put("title", report.title)
        root.put("generatedAt", report.generatedAt.toString())
        root.put("status", report.status.name)

        // Target devices
        val devicesArray = JSONArray()
        for (device in report.targetDevices) {
            val deviceObj = JSONObject()
            deviceObj.put("address", device.address)
            deviceObj.put("name", device.name ?: "Unknown")
            devicesArray.put(deviceObj)
        }
        root.put("targetDevices", devicesArray)

        // Vulnerabilities
        val vulnsArray = JSONArray()
        for (vuln in report.vulnerabilities) {
            val vulnObj = JSONObject()
            vulnObj.put("cveId", vuln.cveId)
            vulnObj.put("name", vuln.name)
            vulnObj.put("severity", vuln.severity.name)
            vulnObj.put("cvssScore", vuln.cvssScore)
            vulnsArray.put(vulnObj)
        }
        root.put("vulnerabilities", vulnsArray)

        // Findings
        val findingsArray = JSONArray()
        for (finding in report.findings) {
            val findingObj = JSONObject()
            findingObj.put("category", finding.category.name)
            findingObj.put("severity", finding.severity.name)
            findingObj.put("count", finding.count)
            findingObj.put("description", finding.description)
            findingsArray.put(findingObj)
        }
        root.put("findings", findingsArray)

        // Executive summary
        root.put("executiveSummary", report.executiveSummary)

        return root.toString(2)
    }

    /**
     * Export report as HTML document.
     */
    fun toHtml(report: SecurityReport): String {
        return buildString {
            appendLine("<!DOCTYPE html>")
            appendLine("<html lang=\"en\"><head><meta charset=\"UTF-8\">")
            appendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">")
            appendLine("<title>${escapeHtml(report.title)}</title>")
            appendLine("<style>")
            appendLine("body { font-family: 'Segoe UI', system-ui, sans-serif; background: #1a1a2e; color: #eee; padding: 2rem; }")
            appendLine("h1 { color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 0.5rem; }")
            appendLine("h2 { color: #7b68ee; margin-top: 2rem; }")
            appendLine("table { width: 100%; border-collapse: collapse; margin: 1rem 0; }")
            appendLine("th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #333; }")
            appendLine("th { background: #16213e; color: #00d4ff; }")
            appendLine(".critical { color: #ff4444; font-weight: bold; }")
            appendLine(".high { color: #ff8800; font-weight: bold; }")
            appendLine(".medium { color: #ffcc00; }")
            appendLine(".low { color: #44ff44; }")
            appendLine(".summary { background: #16213e; padding: 1.5rem; border-radius: 8px; margin: 1rem 0; white-space: pre-wrap; }")
            appendLine("</style></head><body>")
            appendLine("<h1>🔒 ${escapeHtml(report.title)}</h1>")
            appendLine("<p>Generated: ${report.generatedAt} | Status: ${report.status}</p>")

            // Executive summary
            appendLine("<h2>Executive Summary</h2>")
            appendLine("<div class=\"summary\">${escapeHtml(report.executiveSummary)}</div>")

            // Target devices
            appendLine("<h2>Target Devices</h2><table><tr><th>Address</th><th>Name</th><th>Type</th></tr>")
            report.targetDevices.forEach { device ->
                appendLine("<tr><td>${escapeHtml(device.address)}</td><td>${escapeHtml(device.name ?: "Unknown")}</td><td>${escapeHtml(device.type.name)}</td></tr>")
            }
            appendLine("</table>")

            // Vulnerabilities
            if (report.vulnerabilities.isNotEmpty()) {
                appendLine("<h2>Vulnerabilities Detected</h2><table>")
                appendLine("<tr><th>CVE</th><th>Name</th><th>Severity</th><th>CVSS</th></tr>")
                report.vulnerabilities.forEach { vuln ->
                    val cssClass = vuln.severity.name.lowercase()
                    appendLine("<tr><td>${escapeHtml(vuln.cveId ?: "")}</td><td>${escapeHtml(vuln.name)}</td><td class=\"$cssClass\">${vuln.severity}</td><td>${vuln.cvssScore}</td></tr>")
                }
                appendLine("</table>")
            }

            // Findings
            appendLine("<h2>Findings</h2><table><tr><th>Category</th><th>Severity</th><th>Count</th><th>Description</th></tr>")
            report.findings.forEach { finding ->
                val cssClass = finding.severity.name.lowercase()
                appendLine("<tr><td>${escapeHtml(finding.category.name)}</td><td class=\"$cssClass\">${finding.severity}</td><td>${finding.count}</td><td>${escapeHtml(finding.description)}</td></tr>")
            }
            appendLine("</table>")

            // Recommendations
            if (report.recommendations.isNotEmpty()) {
                appendLine("<h2>Recommendations</h2><table><tr><th>Priority</th><th>Title</th><th>Implementation</th></tr>")
                report.recommendations.forEach { rec ->
                    appendLine("<tr><td>${rec.priority}</td><td>${escapeHtml(rec.title)}</td><td>${escapeHtml(rec.implementation)}</td></tr>")
                }
                appendLine("</table>")
            }

            appendLine("<hr><p><em>Generated by BTSec TestTool</em></p>")
            appendLine("</body></html>")
        }
    }

    /**
     * Export report as CSV string.
     */
    fun toCsv(report: SecurityReport): String {
        val sb = StringBuilder()
        sb.appendLine("Type,CVE/ID,Name,Severity,CVSS,Description")

        report.vulnerabilities.forEach { vuln ->
            sb.appendLine("Vulnerability,${vuln.cveId},${escapeCsv(vuln.name)},${vuln.severity},${vuln.cvssScore},${escapeCsv(vuln.description)}")
        }
        report.findings.forEach { finding ->
            sb.appendLine("Finding,-,${finding.category},${finding.severity},${finding.count},${escapeCsv(finding.description)}")
        }
        report.recommendations.forEach { rec ->
            sb.appendLine("Recommendation,-,${escapeCsv(rec.title)},${rec.priority},-,${escapeCsv(rec.implementation)}")
        }
        return sb.toString()
    }

    // ── Helpers ──

    /**
     * Escape a string for safe inclusion in JSON string values.
     *
     * Handles all characters that require escaping per RFC 8259 §7:
     * quotation mark, reverse solidus, and all control characters (U+0000–U+001F).
     *
     * This method is retained for backward compatibility. New code should
     * prefer [JSONObject]/[JSONArray] which handle escaping automatically.
     */
    internal fun escapeJson(s: String): String {
        val sb = StringBuilder(s.length + 16)
        for (ch in s) {
            when (ch) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                '\b' -> sb.append("\\b")
                '\u000C' -> sb.append("\\f")  // form feed
                else -> {
                    if (ch.code < 0x20) {
                        // Other control characters → \uXXXX
                        sb.append("\\u")
                        sb.append(String.format("%04x", ch.code))
                    } else {
                        sb.append(ch)
                    }
                }
            }
        }
        return sb.toString()
    }

    private fun escapeHtml(s: String): String =
        s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")

    private fun escapeCsv(s: String): String =
        if (s.contains(',') || s.contains('"') || s.contains('\n')) "\"${s.replace("\"", "\"\"")}\"" else s
}
