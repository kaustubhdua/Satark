package com.satark.mobile

import java.io.File
import java.util.concurrent.TimeUnit

/** Removes abandoned scan copies after crashes or process termination. */
internal object ScanTempFiles {
    private val prefixes = listOf("satark-scan-", "satark-folder-")
    private val staleAfterMs = TimeUnit.HOURS.toMillis(6)

    fun cleanup(cacheDir: File, nowMs: Long = System.currentTimeMillis()): Int {
        val files = cacheDir.listFiles() ?: return 0
        var deleted = 0
        files.forEach { file ->
            if (file.isFile && prefixes.any { file.name.startsWith(it) } &&
                nowMs - file.lastModified() >= staleAfterMs
            ) {
                if (file.delete()) deleted += 1
            }
        }
        return deleted
    }
}
