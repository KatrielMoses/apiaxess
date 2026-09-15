package com.apiaxess.client.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.Dp
import com.apiaxess.client.ui.theme.Accent

/**
 * The APIaxess mark, drawn from the identity-kit path geometry (viewBox 200x200).
 * Dark-UI variant: the bracket and the far arrow are [inkColor] (white on Ink),
 * the crossbar and near arrow are the [accent].
 */
@Composable
fun ApiaxessMark(
    size: Dp,
    inkColor: Color = Color.White,
    accent: Color = Accent,
    modifier: Modifier = Modifier,
) {
    Canvas(modifier = modifier.size(size)) {
        val scale = this.size.minDimension / 200f
        val stroke = Stroke(width = 14f * scale, cap = StrokeCap.Round, join = StrokeJoin.Round)
        fun p(x: Float, y: Float) = Offset(x * scale, y * scale)

        // Outer bracket: M138 60 L100 22 L22 100 L100 178 L138 140
        val bracket = Path().apply {
            moveTo(p(138f, 60f).x, p(138f, 60f).y)
            lineTo(p(100f, 22f).x, p(100f, 22f).y)
            lineTo(p(22f, 100f).x, p(22f, 100f).y)
            lineTo(p(100f, 178f).x, p(100f, 178f).y)
            lineTo(p(138f, 140f).x, p(138f, 140f).y)
        }
        drawPath(bracket, color = inkColor, style = stroke)

        // Crossbar: M50 100 H140
        val crossbar = Path().apply {
            moveTo(p(50f, 100f).x, p(50f, 100f).y)
            lineTo(p(140f, 100f).x, p(140f, 100f).y)
        }
        drawPath(crossbar, color = accent, style = stroke)

        // Near arrow (accent): M118 78 L142 100 L118 122
        val nearArrow = Path().apply {
            moveTo(p(118f, 78f).x, p(118f, 78f).y)
            lineTo(p(142f, 100f).x, p(142f, 100f).y)
            lineTo(p(118f, 122f).x, p(118f, 122f).y)
        }
        drawPath(nearArrow, color = accent, style = stroke)

        // Far arrow (ink): M168 78 L142 100 L168 122
        val farArrow = Path().apply {
            moveTo(p(168f, 78f).x, p(168f, 78f).y)
            lineTo(p(142f, 100f).x, p(142f, 100f).y)
            lineTo(p(168f, 122f).x, p(168f, 122f).y)
        }
        drawPath(farArrow, color = inkColor, style = stroke)
    }
}
