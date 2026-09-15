package com.apiaxess.client.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.apiaxess.client.ui.theme.Accent
import com.apiaxess.client.ui.theme.Muted
import com.apiaxess.client.ui.theme.OnSurface

/** Uppercase, wide-tracked section label, matching the identity kit. */
@Composable
fun SectionLabel(text: String, modifier: Modifier = Modifier) {
    Text(
        text = text.uppercase(),
        color = Muted,
        fontSize = 11.sp,
        letterSpacing = 2.sp,
        modifier = modifier,
    )
}

/** The horizontal brand lockup: mark + "apiaxess" wordmark. */
@Composable
fun BrandLockup(modifier: Modifier = Modifier) {
    Row(verticalAlignment = Alignment.CenterVertically, modifier = modifier) {
        ApiaxessMark(size = 30.dp)
        Spacer(Modifier.width(12.dp))
        Text(
            text = "apiaxess",
            color = OnSurface,
            fontSize = 24.sp,
            letterSpacing = (-0.5).sp,
        )
    }
}

/** A small coloured status pill (e.g. connected / capturing / error). */
@Composable
fun StatusPill(text: String, color: Color, modifier: Modifier = Modifier) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        modifier = modifier
            .clip(RoundedCornerShape(999.dp))
            .background(color.copy(alpha = 0.14f))
            .padding(horizontal = 12.dp, vertical = 6.dp),
    ) {
        Spacer(
            Modifier
                .size(8.dp)
                .clip(CircleShape)
                .background(color),
        )
        Text(text = text, color = color, fontSize = 13.sp)
    }
}

/** One-line key/value row for the status detail list. */
@Composable
fun DetailRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label, color = Muted, fontSize = 13.sp)
        Spacer(Modifier.width(16.dp))
        Text(
            value,
            color = OnSurface,
            fontSize = 13.sp,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

/** Accent used consistently for interactive affordances. */
val InteractiveAccent: Color = Accent
