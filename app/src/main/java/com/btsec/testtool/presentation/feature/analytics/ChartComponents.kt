/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation.feature.analytics

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.drawText
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.btsec.testtool.domain.model.RiskSeverity
import com.btsec.testtool.domain.model.TrendPoint
import kotlin.math.cos
import kotlin.math.min
import kotlin.math.sin

/**
 * Line chart showing risk score trends over time with colored severity zones.
 *
 * X axis = time (session labels), Y axis = risk score (0-10).
 * Colored zones: CRITICAL(9-10) red, HIGH(7-9) orange, MEDIUM(4-7) yellow, LOW(0-4) green.
 */
@Composable
fun RiskTrendChart(
    trendData: List<TrendPoint>,
    modifier: Modifier = Modifier
) {
    val textMeasurer = rememberTextMeasurer()
    val textStyle = MaterialTheme.typography.labelSmall
    val criticalColor = Color(0xFFE53935)
    val highColor = Color(0xFFFB8C00)
    val mediumColor = Color(0xFFFDD835)
    val lowColor = Color(0xFF43A047)
    val lineColor = MaterialTheme.colorScheme.primary
    val dotColor = MaterialTheme.colorScheme.onSurface

    Column(modifier = modifier) {
        Text(
            text = "Risk Score Trend",
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.padding(bottom = 8.dp)
        )

        Canvas(
            modifier = Modifier
                .fillMaxWidth()
                .height(220.dp)
        ) {
            val chartLeft = 40f
            val chartTop = 10f
            val chartRight = size.width - 10f
            val chartBottom = size.height - 30f
            val chartWidth = chartRight - chartLeft
            val chartHeight = chartBottom - chartTop

            // Draw colored severity zones
            // CRITICAL zone: 9-10
            drawRect(
                color = criticalColor.copy(alpha = 0.15f),
                topLeft = Offset(chartLeft, chartTop),
                size = Size(chartWidth, chartHeight * (1f - 9f / 10f))
            )
            // HIGH zone: 7-9
            drawRect(
                color = highColor.copy(alpha = 0.15f),
                topLeft = Offset(chartLeft, chartTop + chartHeight * (1f - 9f / 10f)),
                size = Size(chartWidth, chartHeight * 2f / 10f)
            )
            // MEDIUM zone: 4-7
            drawRect(
                color = mediumColor.copy(alpha = 0.15f),
                topLeft = Offset(chartLeft, chartTop + chartHeight * (1f - 7f / 10f)),
                size = Size(chartWidth, chartHeight * 3f / 10f)
            )
            // LOW zone: 0-4
            drawRect(
                color = lowColor.copy(alpha = 0.15f),
                topLeft = Offset(chartLeft, chartTop + chartHeight * (1f - 4f / 10f)),
                size = Size(chartWidth, chartHeight * 4f / 10f)
            )

            // Draw Y axis labels
            val yLabels = listOf(0f, 2f, 4f, 6f, 8f, 10f)
            for (label in yLabels) {
                val y = chartBottom - (label / 10f) * chartHeight
                drawText(
                    textMeasurer = textMeasurer,
                    text = label.toInt().toString(),
                    topLeft = Offset(0f, y - 6f),
                    style = textStyle
                )
                // Grid line
                drawLine(
                    color = Color.Gray.copy(alpha = 0.3f),
                    start = Offset(chartLeft, y),
                    end = Offset(chartRight, y),
                    strokeWidth = 1f,
                    pathEffect = PathEffect.dashPathEffect(floatArrayOf(4f, 4f))
                )
            }

            if (trendData.isEmpty()) {
                return@Canvas
            }

            // Draw X axis labels and compute point positions
            val points = mutableListOf<Offset>()
            val xStep = if (trendData.size > 1) {
                chartWidth / (trendData.size - 1)
            } else {
                0f
            }

            for ((index, point) in trendData.withIndex()) {
                val x = if (trendData.size > 1) {
                    chartLeft + index * xStep
                } else {
                    chartLeft + chartWidth / 2f
                }
                val y = chartBottom - (point.riskScore.toFloat().coerceIn(0f, 10f) / 10f) * chartHeight
                points.add(Offset(x, y))

                // Draw X label
                val labelWidth = textMeasurer.measure(point.sessionLabel, textStyle).size.width
                drawText(
                    textMeasurer = textMeasurer,
                    text = point.sessionLabel,
                    topLeft = Offset(x - labelWidth / 2f, chartBottom + 4f),
                    style = textStyle
                )
            }

            // Draw line connecting trend points
            if (points.size > 1) {
                for (i in 0 until points.size - 1) {
                    drawLine(
                        color = lineColor,
                        start = points[i],
                        end = points[i + 1],
                        strokeWidth = 3f
                    )
                }
            }

            // Draw dots at each point
            for (point in points) {
                drawCircle(
                    color = dotColor,
                    radius = 5f,
                    center = point
                )
                drawCircle(
                    color = lineColor,
                    radius = 3f,
                    center = point
                )
            }
        }
    }
}

/**
 * Donut chart showing severity distribution.
 *
 * Arc for each severity with appropriate color.
 * Center text showing total count.
 * Legend below the chart.
 */
@Composable
fun SeverityDonutChart(
    distribution: Map<RiskSeverity, Int>,
    modifier: Modifier = Modifier
) {
    val textMeasurer = rememberTextMeasurer()
    val textStyle = MaterialTheme.typography.labelMedium
    val totalText = MaterialTheme.typography.headlineMedium

    val severityColors = mapOf(
        RiskSeverity.CRITICAL to Color(0xFFE53935),
        RiskSeverity.HIGH to Color(0xFFFB8C00),
        RiskSeverity.MEDIUM to Color(0xFFFDD835),
        RiskSeverity.LOW to Color(0xFF43A047),
        RiskSeverity.INFO to Color(0xFF90A4AE)
    )

    val total = distribution.values.sum()

    val surfaceColor = MaterialTheme.colorScheme.surface
    val onSurfaceColor = MaterialTheme.colorScheme.onSurface

    Column(
        modifier = modifier,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = "Severity Distribution",
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.padding(bottom = 8.dp)
        )

        Canvas(
            modifier = Modifier
                .fillMaxWidth()
                .height(200.dp)
        ) {
            val centerX = size.width / 2f
            val centerY = size.height / 2f
            val outerRadius = min(centerX, centerY) - 10f
            val innerRadius = outerRadius * 0.6f

            if (total == 0) {
                // Empty state: draw a gray ring
                drawArc(
                    color = Color.Gray.copy(alpha = 0.3f),
                    startAngle = 0f,
                    sweepAngle = 360f,
                    useCenter = false,
                    topLeft = Offset(centerX - outerRadius, centerY - outerRadius),
                    size = Size(outerRadius * 2, outerRadius * 2),
                    style = Stroke(width = outerRadius - innerRadius)
                )
                // Center text
                val centerTextLayout = textMeasurer.measure("0", totalText)
                drawText(
                    textMeasurer = textMeasurer,
                    text = "0",
                    topLeft = Offset(
                        centerX - centerTextLayout.size.width / 2f,
                        centerY - centerTextLayout.size.height / 2f
                    ),
                    style = totalText
                )
                return@Canvas
            }

            var startAngle = -90f // Start from top

            // Draw arcs for each severity
            for ((severity, count) in distribution) {
                if (count == 0) continue
                val sweepAngle = (count.toFloat() / total) * 360f

                drawArc(
                    color = severityColors[severity] ?: Color.Gray,
                    startAngle = startAngle,
                    sweepAngle = sweepAngle,
                    useCenter = true,
                    topLeft = Offset(centerX - outerRadius, centerY - outerRadius),
                    size = Size(outerRadius * 2, outerRadius * 2)
                )

                startAngle += sweepAngle
            }

            // Inner circle (donut hole)
            drawCircle(
                color = surfaceColor,
                radius = innerRadius,
                center = Offset(centerX, centerY)
            )

            // Center text
            val centerTextLayout = textMeasurer.measure(total.toString(), totalText)
            drawText(
                textMeasurer = textMeasurer,
                text = total.toString(),
                topLeft = Offset(
                    centerX - centerTextLayout.size.width / 2f,
                    centerY - centerTextLayout.size.height / 2f
                ),
                style = totalText.copy(color = onSurfaceColor)
            )
        }

        // Legend
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 8.dp),
            horizontalArrangement = Arrangement.SpaceEvenly
        ) {
            for ((severity, color) in severityColors) {
                val count = distribution[severity] ?: 0
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.padding(end = 4.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .size(10.dp)
                            .background(color, CircleShape)
                    )
                    Spacer(modifier = Modifier.width(4.dp))
                    Text(
                        text = "${severity.name}: $count",
                        style = MaterialTheme.typography.labelSmall
                    )
                }
            }
        }
    }
}

/**
 * Horizontal bar chart showing category breakdown sorted by count descending.
 */
@Composable
fun CategoryBarChart(
    breakdown: Map<String, Int>,
    modifier: Modifier = Modifier
) {
    val textMeasurer = rememberTextMeasurer()
    val textStyle = MaterialTheme.typography.labelMedium
    val barColor = MaterialTheme.colorScheme.primary
    val labelColor = MaterialTheme.colorScheme.onSurface

    val sortedEntries = breakdown.entries.sortedByDescending { it.value }
    val maxValue = sortedEntries.maxOfOrNull { it.value }?.toFloat() ?: 0f

    Column(modifier = modifier) {
        Text(
            text = "Category Breakdown",
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.padding(bottom = 8.dp)
        )

        if (sortedEntries.isEmpty()) {
            Text(
                text = "No data available",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            return
        }

        Canvas(
            modifier = Modifier
                .fillMaxWidth()
                .height((sortedEntries.size * 40f + 10f).dp)
        ) {
            val labelWidth = 80f
            val valueWidth = 40f
            val barMaxWidth = size.width - labelWidth - valueWidth - 20f
            val barHeight = 20f
            val barSpacing = 40f

            for ((index, entry) in sortedEntries.withIndex()) {
                val y = index * barSpacing + 10f
                val barWidth = if (maxValue > 0f) {
                    (entry.value.toFloat() / maxValue) * barMaxWidth
                } else {
                    0f
                }

                // Category label
                drawText(
                    textMeasurer = textMeasurer,
                    text = entry.key,
                    topLeft = Offset(0f, y + 2f),
                    style = textStyle.copy(color = labelColor)
                )

                // Bar background
                drawRect(
                    color = barColor.copy(alpha = 0.2f),
                    topLeft = Offset(labelWidth, y),
                    size = Size(barMaxWidth, barHeight),
                )

                // Bar fill
                drawRect(
                    color = barColor,
                    topLeft = Offset(labelWidth, y),
                    size = Size(barWidth, barHeight)
                )

                // Value label
                drawText(
                    textMeasurer = textMeasurer,
                    text = entry.value.toString(),
                    topLeft = Offset(labelWidth + barMaxWidth + 8f, y + 2f),
                    style = textStyle.copy(color = labelColor)
                )
            }
        }
    }
}
