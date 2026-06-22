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
import com.itextpdf.kernel.colors.ColorConstants
import com.itextpdf.kernel.colors.DeviceRgb
import com.itextpdf.kernel.pdf.PdfDocument
import com.itextpdf.kernel.pdf.PdfWriter
import com.itextpdf.layout.Document
import com.itextpdf.layout.element.Cell
import com.itextpdf.layout.element.Paragraph
import com.itextpdf.layout.element.Table
import com.itextpdf.layout.properties.UnitValue
import java.io.ByteArrayOutputStream
import java.text.SimpleDateFormat
import java.util.Locale
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Export formatters for security reports.
 * Supports JSON, HTML, CSV, and PDF output formats.
 * PDF generation uses iText 7.
 */
@Singleton
class ExportFormatters
    @Inject
    constructor() {
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
                        appendLine(
                            "<tr><td>${vuln.cveId}</td><td>${escapeHtml(
                                vuln.name,
                            )}</td><td class=\"$cssClass\">${vuln.severity}</td><td>${vuln.cvssScore}</td></tr>",
                        )
                    }
                    appendLine("</table>")
                }

                // Findings
                appendLine("<h2>Findings</h2><table><tr><th>Category</th><th>Severity</th><th>Count</th><th>Description</th></tr>")
                report.findings.forEach { finding ->
                    val cssClass = finding.severity.name.lowercase()
                    appendLine(
                        "<tr><td>${finding.category}</td><td class=\"$cssClass\">${finding.severity}</td><td>${finding.count}</td><td>${escapeHtml(
                            finding.description,
                        )}</td></tr>",
                    )
                }
                appendLine("</table>")

                // Recommendations
                if (report.recommendations.isNotEmpty()) {
                    appendLine("<h2>Recommendations</h2><table><tr><th>Priority</th><th>Title</th><th>Implementation</th></tr>")
                    report.recommendations.forEach { rec ->
                        appendLine(
                            "<tr><td>${rec.priority}</td><td>${escapeHtml(rec.title)}</td><td>${escapeHtml(rec.implementation)}</td></tr>",
                        )
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
                sb.appendLine(
                    "Vulnerability,${vuln.cveId},${escapeCsv(vuln.name)},${vuln.severity},${vuln.cvssScore},${escapeCsv(vuln.description)}",
                )
            }
            report.findings.forEach { finding ->
                sb.appendLine("Finding,-,${finding.category},${finding.severity},${finding.count},${escapeCsv(finding.description)}")
            }
            report.recommendations.forEach { rec ->
                sb.appendLine("Recommendation,-,${escapeCsv(rec.title)},${rec.priority},-,${escapeCsv(rec.implementation)}")
            }
            return sb.toString()
        }

        /**
         * Export report as PDF using iText 7.
         *
         * Generates a structured PDF document with:
         * - Title and metadata header
         * - Executive summary
         * - Target devices table
         * - Vulnerabilities table (color-coded severity)
         * - Findings table
         * - Recommendations table
         *
         * @return ByteArray containing the raw PDF bytes
         */
        fun toPdf(report: SecurityReport): ByteArray {
            val baos = ByteArrayOutputStream()
            val pdfWriter = PdfWriter(baos)
            val pdfDoc = PdfDocument(pdfWriter)
            val document = Document(pdfDoc)

            // Colors
            val cyanTitle = DeviceRgb(0, 212, 255)
            val purpleHeading = DeviceRgb(123, 104, 238)
            val darkBg = DeviceRgb(22, 33, 62)
            val critColor = DeviceRgb(255, 68, 68)
            val highColor = DeviceRgb(255, 136, 0)
            val medColor = DeviceRgb(255, 204, 0)
            val lowColor = DeviceRgb(68, 255, 68)

            // Title
            document.add(
                Paragraph("🔒 ${report.title}")
                    .setFontSize(22f)
                    .setFontColor(cyanTitle)
                    .setMarginBottom(4f),
            )
            document.add(
                Paragraph("Generated: ${report.generatedAt} | Status: ${report.status.name} | ID: ${report.id}")
                    .setFontSize(9f)
                    .setFontColor(ColorConstants.GRAY)
                    .setMarginBottom(16f),
            )

            // Executive Summary
            document.add(
                Paragraph("Executive Summary")
                    .setFontSize(16f)
                    .setFontColor(purpleHeading)
                    .setMarginTop(16f)
                    .setMarginBottom(8f),
            )
            document.add(
                Paragraph(report.executiveSummary)
                    .setFontSize(10f)
                    .setMarginBottom(12f),
            )

            // Test Period
            document.add(
                Paragraph("Test Period: ${report.testPeriod.start} — ${report.testPeriod.end}")
                    .setFontSize(9f)
                    .setFontColor(ColorConstants.GRAY)
                    .setMarginBottom(12f),
            )

            // Target Devices Table
            if (report.targetDevices.isNotEmpty()) {
                document.add(
                    Paragraph("Target Devices")
                        .setFontSize(14f)
                        .setFontColor(purpleHeading)
                        .setMarginTop(16f)
                        .setMarginBottom(8f),
                )
                val deviceTable =
                    Table(UnitValue.createPercentArray(floatArrayOf(35f, 35f, 30f)))
                        .useAllAvailableWidth()
                        .setMarginBottom(12f)
                deviceTable.addHeaderCell(headerCell("Address"))
                deviceTable.addHeaderCell(headerCell("Name"))
                deviceTable.addHeaderCell(headerCell("Type"))
                report.targetDevices.forEach { device ->
                    deviceTable.addCell(dataCell(device.address))
                    deviceTable.addCell(dataCell(device.name ?: "Unknown"))
                    deviceTable.addCell(dataCell(device.type.name))
                }
                document.add(deviceTable)
            }

            // Vulnerabilities Table
            if (report.vulnerabilities.isNotEmpty()) {
                document.add(
                    Paragraph("Vulnerabilities Detected")
                        .setFontSize(14f)
                        .setFontColor(purpleHeading)
                        .setMarginTop(16f)
                        .setMarginBottom(8f),
                )
                val vulnTable =
                    Table(UnitValue.createPercentArray(floatArrayOf(15f, 30f, 20f, 15f, 20f)))
                        .useAllAvailableWidth()
                        .setMarginBottom(12f)
                vulnTable.addHeaderCell(headerCell("CVE"))
                vulnTable.addHeaderCell(headerCell("Name"))
                vulnTable.addHeaderCell(headerCell("Severity"))
                vulnTable.addHeaderCell(headerCell("CVSS"))
                vulnTable.addHeaderCell(headerCell("Category"))
                report.vulnerabilities.forEach { vuln ->
                    vulnTable.addCell(dataCell(vuln.cveId ?: "N/A"))
                    vulnTable.addCell(dataCell(vuln.name))
                    val sevColor = severityColor(vuln.severity, critColor, highColor, medColor, lowColor)
                    vulnTable.addCell(
                        Cell().add(
                            Paragraph(vuln.severity.name)
                                .setFontColor(sevColor)
                                .setFontSize(9f)
                                .setBold(),
                        ),
                    )
                    vulnTable.addCell(dataCell(vuln.cvssScore?.toString() ?: "N/A"))
                    vulnTable.addCell(dataCell(vuln.category.name))
                }
                document.add(vulnTable)
            }

            // Findings Table
            if (report.findings.isNotEmpty()) {
                document.add(
                    Paragraph("Findings")
                        .setFontSize(14f)
                        .setFontColor(purpleHeading)
                        .setMarginTop(16f)
                        .setMarginBottom(8f),
                )
                val findingTable =
                    Table(UnitValue.createPercentArray(floatArrayOf(25f, 20f, 10f, 45f)))
                        .useAllAvailableWidth()
                        .setMarginBottom(12f)
                findingTable.addHeaderCell(headerCell("Category"))
                findingTable.addHeaderCell(headerCell("Severity"))
                findingTable.addHeaderCell(headerCell("Count"))
                findingTable.addHeaderCell(headerCell("Description"))
                report.findings.forEach { finding ->
                    findingTable.addCell(dataCell(finding.category.name))
                    val sevColor = severityColor(finding.severity, critColor, highColor, medColor, lowColor)
                    findingTable.addCell(
                        Cell().add(
                            Paragraph(finding.severity.name)
                                .setFontColor(sevColor)
                                .setFontSize(9f)
                                .setBold(),
                        ),
                    )
                    findingTable.addCell(dataCell(finding.count.toString()))
                    findingTable.addCell(dataCell(finding.description))
                }
                document.add(findingTable)
            }

            // Recommendations Table
            if (report.recommendations.isNotEmpty()) {
                document.add(
                    Paragraph("Recommendations")
                        .setFontSize(14f)
                        .setFontColor(purpleHeading)
                        .setMarginTop(16f)
                        .setMarginBottom(8f),
                )
                val recTable =
                    Table(UnitValue.createPercentArray(floatArrayOf(15f, 30f, 55f)))
                        .useAllAvailableWidth()
                        .setMarginBottom(12f)
                recTable.addHeaderCell(headerCell("Priority"))
                recTable.addHeaderCell(headerCell("Title"))
                recTable.addHeaderCell(headerCell("Implementation"))
                report.recommendations.forEach { rec ->
                    recTable.addCell(dataCell(rec.priority.name))
                    recTable.addCell(dataCell(rec.title))
                    recTable.addCell(dataCell(rec.implementation))
                }
                document.add(recTable)
            }

            // Footer
            document.add(
                Paragraph("—")
                    .setMarginTop(20f)
                    .setFontColor(ColorConstants.GRAY),
            )
            document.add(
                Paragraph("Generated by BTSec TestTool")
                    .setFontSize(9f)
                    .setFontColor(ColorConstants.GRAY),
            )

            document.close()
            return baos.toByteArray()
        }

        // ── PDF helper builders ──

        private fun headerCell(text: String): Cell {
            return Cell().add(
                Paragraph(text).setFontSize(9f).setBold().setFontColor(ColorConstants.WHITE),
            ).setBackgroundColor(DeviceRgb(22, 33, 62))
        }

        private fun dataCell(text: String): Cell {
            return Cell().add(
                Paragraph(text).setFontSize(9f),
            )
        }

        private fun severityColor(
            severity: VulnerabilitySeverity,
            critical: DeviceRgb,
            high: DeviceRgb,
            medium: DeviceRgb,
            low: DeviceRgb,
        ) = when (severity) {
            VulnerabilitySeverity.CRITICAL -> critical
            VulnerabilitySeverity.HIGH -> high
            VulnerabilitySeverity.MEDIUM -> medium
            VulnerabilitySeverity.LOW -> low
            else -> ColorConstants.GRAY
        }

        // ── String Helpers ──

        private fun escapeJson(s: String): String = s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")

        private fun escapeHtml(s: String): String =
            s.replace(
                "&",
                "&amp;",
            ).replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")

        private fun escapeCsv(s: String): String =
            if (s.contains(',') || s.contains('"') || s.contains('\n')) "\"${s.replace("\"", "\"\"")}\"" else s
    }
