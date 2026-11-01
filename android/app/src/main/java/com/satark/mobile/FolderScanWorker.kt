package com.satark.mobile

import android.content.Context
import android.net.Uri
import androidx.documentfile.provider.DocumentFile
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform
import java.io.ByteArrayOutputStream

class FolderScanWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        val rawUri = inputData.getString(KEY_TREE_URI)
            ?: applicationContext.getSharedPreferences("satark_file_guard", Context.MODE_PRIVATE)
                .getString("granted_tree_uri", null)
            ?: return Result.failure()
        val root = DocumentFile.fromTreeUri(applicationContext, Uri.parse(rawUri))
            ?: return Result.failure()
        if (!root.isDirectory || !root.canRead()) return Result.failure()

        try {
            if (!Python.isStarted()) Python.start(AndroidPlatform(applicationContext))
            val bridge = Python.getInstance().getModule("android_bridge")
            var scanned = 0
            var totalBytes = 0L
            val pending = ArrayDeque<Pair<DocumentFile, Int>>()
            pending.add(root to 0)
            while (pending.isNotEmpty() && scanned < MAX_FILES && !isStopped) {
                val (directory, depth) = pending.removeFirst()
                val children = try { directory.listFiles() } catch (_: Exception) { emptyArray() }
                for (child in children) {
                    if (isStopped || scanned >= MAX_FILES) break
                    if (child.isDirectory) {
                        if (depth < MAX_DEPTH) pending.add(child to depth + 1)
                        continue
                    }
                    if (!child.isFile || !child.canRead()) continue
                    val declaredSize = child.length()
                    if (declaredSize > MAX_FILE_BYTES) continue
                    if (declaredSize > 0 && totalBytes + declaredSize > MAX_TOTAL_BYTES) break
                    try {
                        val bytes = readBounded(child.uri)
                        totalBytes += bytes.size
                        bridge.callAttr("scan_shared_file", bytes, child.name ?: "document", applicationContext.filesDir.absolutePath)
                        scanned += 1
                    } catch (_: Exception) {
                        // Keep scanning other granted files; failures are not safety verdicts.
                    }
                }
            }
            return Result.success(androidx.work.workDataOf("scanned_files" to scanned, "scanned_bytes" to totalBytes))
        } catch (_: Exception) {
            return Result.retry()
        }
    }

    private fun readBounded(uri: Uri): ByteArray {
        val output = ByteArrayOutputStream()
        applicationContext.contentResolver.openInputStream(uri)?.use { input ->
            val buffer = ByteArray(64 * 1024)
            var total = 0L
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                total += count
                if (total > MAX_FILE_BYTES) throw IllegalArgumentException("File size limit")
                output.write(buffer, 0, count)
            }
        } ?: throw IllegalStateException("Provider cannot open URI")
        return output.toByteArray()
    }

    companion object {
        const val KEY_TREE_URI = "tree_uri"
        const val UNIQUE_PERIODIC_NAME = "satark-file-guard-daily"
        private const val MAX_FILES = 1000
        private const val MAX_DEPTH = 8
        private const val MAX_FILE_BYTES = 64L * 1024L * 1024L
        private const val MAX_TOTAL_BYTES = 512L * 1024L * 1024L
    }
}
