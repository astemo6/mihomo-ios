package io.github.astemo6.mihomo.ui

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object Fmt {
    fun bytes(v: Long): String {
        val units = arrayOf("B", "KB", "MB", "GB", "TB")
        var d = v.coerceAtLeast(0).toDouble()
        var i = 0
        while (d >= 1024 && i < units.size - 1) { d /= 1024; i++ }
        return when {
            i == 0 -> "${d.toLong()} B"
            d >= 100 -> String.format(Locale.US, "%.0f %s", d, units[i])
            else -> String.format(Locale.US, "%.1f %s", d, units[i])
        }
    }

    fun speed(v: Long): String = bytes(v) + "/s"

    fun duration(ms: Long): String {
        val s = (ms / 1000).coerceAtLeast(0)
        return when {
            s < 60 -> "${s}s"
            s < 3600 -> "${s / 60}m${s % 60}s"
            s < 86400 -> "${s / 3600}h${(s % 3600) / 60}m"
            else -> "${s / 86400}d${(s % 86400) / 3600}h"
        }
    }

    fun date(epochMs: Long): String = SimpleDateFormat("yyyy-MM-dd", Locale.getDefault()).format(Date(epochMs))
    fun dateTime(epochMs: Long): String = SimpleDateFormat("MM-dd HH:mm", Locale.getDefault()).format(Date(epochMs))
    fun time(epochMs: Long): String = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(epochMs))
}
