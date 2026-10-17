package io.github.astemo6.mihomo.data

import io.github.astemo6.mihomo.core.Paths
import kotlinx.serialization.Serializable
import java.io.File
import java.util.UUID

@Serializable
data class SubscriptionUserInfo(
    val upload: Long = 0,
    val download: Long = 0,
    val total: Long = 0,
    /** unix seconds, 0 = none */
    val expire: Long = 0,
) {
    val used: Long get() = upload + download
    val fraction: Float get() = if (total > 0) (used.toDouble() / total).coerceIn(0.0, 1.0).toFloat() else 0f

    companion object {
        /** Parses "upload=123; download=456; total=789; expire=1700000000". */
        fun parse(header: String?): SubscriptionUserInfo? {
            if (header.isNullOrBlank()) return null
            var info = SubscriptionUserInfo()
            var found = false
            for (part in header.split(';', ',')) {
                val kv = part.split('=', limit = 2).map { it.trim().lowercase() }
                if (kv.size != 2) continue
                val v = kv[1].toDoubleOrNull()?.toLong() ?: 0L
                when (kv[0]) {
                    "upload" -> { info = info.copy(upload = v); found = true }
                    "download" -> { info = info.copy(download = v); found = true }
                    "total" -> { info = info.copy(total = v); found = true }
                    "expire" -> { info = info.copy(expire = v); found = true }
                }
            }
            return if (found) info else null
        }
    }
}

@Serializable
data class Profile(
    val id: String = UUID.randomUUID().toString(),
    val name: String,
    val kind: Kind,
    val url: String? = null,
    val userAgent: String = "clash.meta",
    /** 0 = never auto-update */
    val updateIntervalHours: Int = 24,
    /** epoch millis */
    val lastUpdated: Long? = null,
    val userInfo: SubscriptionUserInfo? = null,
) {
    @Serializable
    enum class Kind { remote, local }

    val file: File get() = Paths.profile(id)
    val isRemote: Boolean get() = kind == Kind.remote
}
