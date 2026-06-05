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
     */
    fun toJson(report: SecurityReport): String {
        val sb = StringBuilder()
        sb.appendLine("{")
        sb.appendLine("  \"id\": \"${report.id}\",")
        sb.appendLine("  \"authId\": \"${report.authId}\",")
        sb.appendLine("  \"title\": \"${escapeJson(report.title)}\",")
        sb.appendLine("  \"generatedAt\": \"${report.generatedAt}\",")
        sb.appendLine("  \"status\": \"${report.status}\",")

        // Target devices
        sb.appendLine("  \"targetDevices\": [")
        report.targetDevices.forEachIndexed { i, device ->
            sb.append("    {\"address\": \"${device.address}\", \"name\": \"${escapeJson(device.name ?: "Unknown")}\"}")
            if (i < report.targetDevices.lastIndex) sb.append(",")
            sb.appendLine()
        }
        sb.appendLine("  ],")

        // Vulnerabilities
        sb.appendLine("  \"vulnerabilities\": [")
        report.vulnerabilities.forEachIndexed { i, vuln ->
            sb.appendLine("    {")
            sb.appendLine("      \"cveId\": \"${vuln.cveId}\",")
            sb.appendLine("      \"name\": \"${escapeJson(vuln.name)}\",")
            sb.appendLine("      \"severity\": \"${vuln.severity}\",")
            sb.appendLine("      \"cvssScore\": ${vuln.cvssScore}")
            sb.append("    }")
            if (i < report.vulnerabilities.lastIndex) sb.append(",")
            sb.appendLine()
        }
        sb.appendLine("  ],")

        // Findings
        sb.appendLine("  \"findings\": [")
        report.findings.forEachIndexed { i, finding ->
            sb.appendLine("    {")
            sb.appendLine("      \"category\": \"${finding.category}\",")
            sb.appendLine("      \"severity\": \"${finding.severity}\",")
            sb.appendLine("      \"count\": ${finding.count},")
            sb.appendLine("      \"description\": \"${escapeJson(finding.description)}\"")
            sb.append("    }")
            if (i < report.findings.lastIndex) sb.append(",")
            sb.appendLine()
        }
        sb.appendLine("  ],")

        // Executive summary
        sb.appendLine("  \"executiveSummary\": \"${escapeJson(report.executiveSummary)}\"")
        sb.appendLine("}")
        return sb.toString()
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
                appendLine("<tr><td>${device.address}</td><td>${escapeHtml(device.name ?: "Unknown")}</td><td>${device.type}</td></tr>")
            }
            appendLine("</table>")

            // Vulnerabilities
            if (report.vulnerabilities.isNotEmpty()) {
                appendLine("<h2>Vulnerabilities Detected</h2><table>")
                appendLine("<tr><th>CVE</th><th>Name</th><th>Severity</th><th>CVSS</th></tr>")
                report.vulnerabilities.forEach { vuln ->
                    val cssClass = vuln.severity.name.lowercase()
                    appendLine("<tr><td>${vuln.cveId}</td><td>${escapeHtml(vuln.name)}</td><td class=\"$cssClass\">${vuln.severity}</td><td>${vuln.cvssScore}</td></tr>")
                }
                appendLine("</table>")
            }

            // Findings
            appendLine("<h2>Findings</h2><table><tr><th>Category</th><th>Severity</th><th>Count</th><th>Description</th></tr>")
            report.findings.forEach { finding ->
                val cssClass = finding.severity.name.lowercase()
                appendLine("<tr><td>${finding.category}</td><td class=\"$cssClass\">${finding.severity}</td><td>${finding.count}</td><td>${escapeHtml(finding.description)}</td></tr>")
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

    private fun escapeJson(s: String): String =
        s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")

    private fun escapeHtml(s: String): String =
        s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")

    private fun escapeCsv(s: String): String =
        if (s.contains(',') || s.contains('"') || s.contains('\n')) "\"${s.replace("\"", "\"\"")}\"" else s
}
