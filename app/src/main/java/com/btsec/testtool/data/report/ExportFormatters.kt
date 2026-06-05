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
import java.io.File

/**
 * Exports SecurityReport to various formats.
 */

class JsonExporter {
    fun export(report: SecurityReport): String {
        val sb = StringBuilder()
        sb.appendLine("{")
        sb.appendLine("  \"id\": ${escapeJson(report.id)},")
        sb.appendLine("  \"title\": ${escapeJson(report.title)},")
        sb.appendLine("  \"generatedAt\": ${escapeJson(report.generatedAt.toString())},")
        sb.appendLine("  \"generatedBy\": ${escapeJson(report.generatedBy)},")
        sb.appendLine("  \"status\": ${escapeJson(report.status.name)},")
        sb.appendLine("  \"authId\": ${escapeJson(report.authId)},")
        sb.appendLine("  \"totalRiskScore\": ${report.totalRiskScore},")
        sb.appendLine("  \"executiveSummary\": ${escapeJson(report.executiveSummary ?: "")},")
        sb.appendLine("  \"targetDevices\": [")
        report.targetDevices.forEachIndexed { i, d ->
            sb.appendLine("    {\"address\": ${escapeJson(d.address)}, \"name\": ${escapeJson(d.name)}, \"type\": ${escapeJson(d.type.name)}}${if (i < report.targetDevices.size - 1) "," else ""}")
        }
        sb.appendLine("  ],")
        sb.appendLine("  \"vulnerabilities\": [")
        report.vulnerabilities.forEachIndexed { i, v ->
            sb.appendLine("    {\"id\": ${escapeJson(v.id)}, \"name\": ${escapeJson(v.name)}, \"severity\": ${escapeJson(v.severity.name)}, \"cveId\": ${escapeJson(v.cveId ?: "")}, \"detected\": ${v.detected}, \"verified\": ${v.verified}}${if (i < report.vulnerabilities.size - 1) "," else ""}")
        }
        sb.appendLine("  ],")
        sb.appendLine("  \"fuzzingResults\": [")
        report.fuzzingResults.forEachIndexed { i, f ->
            sb.appendLine("    {\"id\": ${escapeJson(f.id)}, \"method\": ${escapeJson(f.config.fuzzMethod.name)}, \"packetsSent\": ${f.packetsSent}, \"packetsReceived\": ${f.packetsReceived}, \"findings\": ${f.findings.size}}${if (i < report.fuzzingResults.size - 1) "," else ""}")
        }
        sb.appendLine("  ],")
        sb.appendLine("  \"keyExtractionResults\": [")
        report.keyExtractionResults.forEachIndexed { i, k ->
            sb.appendLine("    {\"id\": ${escapeJson(k.id)}, \"keyType\": ${escapeJson(k.keyType.name)}, \"extracted\": ${k.extracted}, \"method\": ${escapeJson(k.method.name)}}${if (i < report.keyExtractionResults.size - 1) "," else ""}")
        }
        sb.appendLine("  ],")
        sb.appendLine("  \"recommendations\": [")
        report.recommendations.forEachIndexed { i, r ->
            sb.appendLine("    ${escapeJson(r)}${if (i < report.recommendations.size - 1) "," else ""}")
        }
        sb.appendLine("  ]")
        sb.appendLine("}")
        return sb.toString()
    }

    private fun escapeJson(s: String): String = "\"${s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")}\""
}

class HtmlExporter {
    fun export(report: SecurityReport): String {
        val riskColor = when {
            (report.totalRiskScore ?: 0.0) >= 8.0 -> "#f44336"
            (report.totalRiskScore ?: 0.0) >= 5.0 -> "#ff9800"
            (report.totalRiskScore ?: 0.0) >= 2.5 -> "#ffc107"
            else -> "#4caf50"
        }
        return """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escHtml(report.title)}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#c9d1d9;padding:40px}
.container{max-width:1000px;margin:0 auto}h1{color:#58a6ff;border-bottom:1px solid #21262d;padding-bottom:16px;margin-bottom:24px}
h2{color:#79c0ff;margin:24px 0 12px}h3{color:#d2a8ff;margin:16px 0 8px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;margin-bottom:16px}
.risk-gauge{width:100%;height:24px;background:#21262d;border-radius:12px;overflow:hidden;margin:8px 0}
.risk-fill{height:100%;background:$riskColor;border-radius:12px;width:${((report.totalRiskScore ?: 0.0) * 10).toInt()}%}
table{width:100%;border-collapse:collapse}th,td{padding:10px 12px;text-align:left;border-bottom:1px solid #21262d}
th{color:#8b949e;font-weight:600;font-size:13px}td{font-size:14px}
.severity-critical{color:#f85149}.severity-high{color:#db6d28}.severity-medium{color:#d29922}.severity-low{color:#3fb950}
.recommendation{background:#0d1117;border-left:3px solid #58a6ff;padding:12px 16px;margin:8px 0;border-radius:0 4px 4px 0}
.summary{line-height:1.7;white-space:pre-wrap}.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:12px;font-weight:600}
.badge-draft{background:#1f2937;color:#9ca3af}.badge-final{background:#0f5323;color:#3fb950}
footer{margin-top:40px;padding-top:16px;border-top:1px solid #21262d;color:#8b949e;font-size:12px}
</style></head><body><div class="container">
<h1>${escHtml(report.title)}</h1>
<div class="card">
<h2>Overview</h2>
<table><tr><th>Generated</th><td>${escHtml(report.generatedAt.toString())}</td></tr>
<tr><th>Status</th><td><span class="badge badge-${report.status.name.lowercase()}">${report.status.name}</span></td></tr>
<tr><th>Risk Score</th><td><strong>${report.totalRiskScore ?: 0.0}/10.0</strong></td></tr></table>
<div class="risk-gauge"><div class="risk-fill"></div></div>
<p>Devices: ${report.targetDevices.size} | Vulnerabilities: ${report.vulnerabilities.size} | Fuzzing Sessions: ${report.fuzzingResults.size}</p>
</div>
${if (report.executiveSummary != null) "<div class=\"card\"><h2>Executive Summary</h2><p class=\"summary\">${escHtml(report.executiveSummary)}</p></div>" else ""}
${if (report.vulnerabilities.isNotEmpty()) "<div class=\"card\"><h2>Vulnerabilities (${report.vulnerabilities.size})</h2><table><tr><th>CVE</th><th>Name</th><th>Severity</th><th>Detected</th><th>Verified</th></tr>${report.vulnerabilities.joinToString("") { v ->
            "<tr><td>${escHtml(v.cveId ?: "N/A")}</td><td>${escHtml(v.name)}</td><td class=\"severity-${v.severity.name.lowercase()}\">${v.severity.name}</td><td>${v.detected}</td><td>${v.verified}</td></tr>"
        }}</table></div>" else ""}
${if (report.fuzzingResults.isNotEmpty()) "<div class=\"card\"><h2>Fuzzing Results</h2><table><tr><th>Session</th><th>Method</th><th>Sent</th><th>Received</th><th>Findings</th></tr>${report.fuzzingResults.joinToString("") { f ->
            "<tr><td>${f.id.take(8)}</td><td>${f.config.fuzzMethod.name}</td><td>${f.packetsSent}</td><td>${f.packetsReceived}</td><td>${f.findings.size}</td></tr>"
        }}</table></div>" else ""}
${if (report.recommendations.isNotEmpty()) "<div class=\"card\"><h2>Recommendations</h2>${report.recommendations.joinToString("") { r -> "<div class=\"recommendation\">${escHtml(r)}</div>" }}</div>" else ""}
<footer>Generated by ${escHtml(report.generatedBy)} | Auth ID: ${escHtml(report.authId.take(8))}***</footer>
</div></body></html>"""
    }

    private fun escHtml(s: String) = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
}

class CsvExporter {
    fun export(report: SecurityReport): String {
        val sb = StringBuilder()
        sb.appendLine("BTSec Security Report: ${report.title}")
        sb.appendLine("Generated,${report.generatedAt}")
        sb.appendLine("Risk Score,${report.totalRiskScore ?: 0.0}")
        sb.appendLine()
        sb.appendLine("VULNERABILITIES")
        sb.appendLine("ID,Name,Severity,CVE,Detected,Verified,Description")
        report.vulnerabilities.forEach { v ->
            sb.appendLine("${csv(v.id)},${csv(v.name)},${v.severity.name},${csv(v.cveId ?: "")},${v.detected},${v.verified},${csv(v.description)}")
        }
        sb.appendLine()
        sb.appendLine("FUZZING RESULTS")
        sb.appendLine("SessionID,Method,PacketsSent,PacketsReceived,Errors,Findings,Status")
        report.fuzzingResults.forEach { f ->
            sb.appendLine("${f.id.take(8)},${f.config.fuzzMethod.name},${f.packetsSent},${f.packetsReceived},${f.errors.size},${f.findings.size},${f.status.name}")
        }
        sb.appendLine()
        sb.appendLine("RECOMMENDATIONS")
        report.recommendations.forEach { r ->
            sb.appendLine(csv(r))
        }
        return sb.toString()
    }

    private fun csv(s: String) = if (s.contains(',') || s.contains('"') || s.contains('\n')) "\"${s.replace("\"", "\"\"")}\"" else s
}

class PdfExporter {
    /**
     * Export report to PDF using Android PdfDocument API.
     *
     * Note: Production use would use a proper PDF library (iText, Apache PDFBox)
     * for rich formatting. This implementation uses the basic Android PdfDocument
     * for simple text-based output.
     */
    fun export(report: SecurityReport, outputPath: String): File {
        val file = File(outputPath)
        // PdfDocument requires Android runtime — write placeholder
        // In production, this would use:
        // val document = android.graphics.pdf.PdfDocument()
        // val pageInfo = PdfDocument.PageInfo.Builder(595, 842, 1).create()
        // val page = document.startPage(pageInfo)
        // val canvas = page.canvas
        // val paint = android.graphics.Paint().apply { textSize = 12f }
        // ... draw text content ...
        // document.finishPage(page)
        // document.writeTo(file.outputStream())
        // document.close()

        // For now, write the HTML version as a fallback
        val htmlContent = HtmlExporter().export(report)
        file.writeText(htmlContent)
        return file
    }
}
