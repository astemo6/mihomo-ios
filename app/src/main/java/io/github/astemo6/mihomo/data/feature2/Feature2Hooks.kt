package io.github.astemo6.mihomo.data.feature2

import android.content.Context

/**
 * Optional one-line hooks for the shared app code (owned by the main branch). Feature2Screen calls
 * [onAppCreate] itself, so everything works without them; wiring them in only widens coverage:
 *  - MihomoApp.onCreate → `Feature2Hooks.onAppCreate(this)`: daily traffic history and the DNS / blocked
 *    log run from app start instead of from the first visit to a feature2 screen.
 *  - app foreground (where ProfileStore.autoUpdateIfNeeded runs) → `Feature2Hooks.onForeground(context)`:
 *    node subscriptions auto-update on the same schedule as profiles (iOS does both on foreground).
 */
object Feature2Hooks {
    fun onAppCreate(context: Context) {
        TrafficStats.ensureStarted(context)
        DnsLog.ensureStarted()
        ProbeStore.load()
    }

    /** Refreshes due node subscriptions; reloads the running core when one changed. */
    suspend fun onForeground(context: Context) {
        if (NodeSubStore.autoUpdateIfNeeded()) F2Core.reload(context)
    }
}
