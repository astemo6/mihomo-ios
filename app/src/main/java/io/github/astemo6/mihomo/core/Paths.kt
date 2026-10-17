package io.github.astemo6.mihomo.core

import android.content.Context
import java.io.File

/**
 * On-disk layout shared with the Go bridge (same as the iOS App Group container):
 *  - home      = filesDir/core          (geo databases, cache.db, overrides.json, runtime.yaml …)
 *  - profiles  = filesDir/profiles      (<id>.yaml; the bridge looks for dirname(home)/profiles/manual-nodes.yaml)
 *  - index     = filesDir/profiles.json (profile metadata list)
 */
object Paths {
    lateinit var root: File
        private set

    fun init(context: Context) {
        root = context.filesDir
        home.mkdirs()
        profiles.mkdirs()
    }

    val home: File get() = File(root, "core")
    val profiles: File get() = File(root, "profiles")
    val profilesIndex: File get() = File(root, "profiles.json")
    val overrides: File get() = File(home, "overrides.json")
    val stageLog: File get() = File(home, "startup.log")

    fun profile(id: String): File = File(profiles, "$id.yaml")
}
