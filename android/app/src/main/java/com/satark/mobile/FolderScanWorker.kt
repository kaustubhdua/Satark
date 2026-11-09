package com.satark.mobile

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.DocumentsContract
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform
import org.json.JSONObject
import java.io.ByteArrayOutputStream

class FolderScanWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        val rawUri = inputData.getString(KEY_TREE_URI)
            ?: applicationContext.getSharedPreferences("satark_file_guard", Context.MODE_PRIVATE)
                .getString("granted_tree_uri", null)
            ?: return Result.failure()
        val treeUri = Uri.parse(rawUri)

        try {
            val rootDocumentId = DocumentsContract.getTreeDocumentId(treeUri)
            if (!Python.isStarted()) Python.start(AndroidPlatform(applicationContext))
            val bridge = Python.getInstance().getModule("android_bridge")
            val pending = ArrayDeque<Pair<String, Int>>()
            pending.add(rootDocumentId to 0)
            var scanned = 0
            var skipped = 0
            var highRisk = 0
            var totalBytes = 0L
            var hitLimit = false
            val projection = arrayOf(
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_MIME_TYPE,
                DocumentsContract.Document.COLUMN_SIZE
            )

            while (pending.isNotEmpty() && scanned < MAX_FILES && !isStopped && !hitLimit) {
                val (parentId, depth) = pending.removeFirst()
                val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, parentId)
                val cursor = applicationContext.contentResolver.query(childrenUri, projection, null, null, null)
                    ?: continue
                cursor.use { rows ->
                    while (rows.moveToNext() && scanned < MAX_FILES && !isStopped && !hitLimit) {
                        val documentId = rows.getString(0) ?: continue
                        val name = rows.getString(1) ?: "document"
                        val mime = rows.getString(2) ?: "application/octet-stream"
                        if (mime == DocumentsContract.Document.MIME_TYPE_DIR) {
                            if (depth < MAX_DEPTH) pending.add(documentId to depth + 1)
                            continue
                        }
                        val size = if (rows.isNull(3)) -1L else rows.getLong(3)
                        if (size > MAX_FILE_BYTES) {
                            skipped += 1
                            continue
                        }
                        try {
                            val documentUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, documentId)
                            val bytes = readBounded(documentUri)
                            if (totalBytes + bytes.size > MAX_TOTAL_BYTES) {
                                hitLimit = true
                                break
                            }
                            val scanJson = bridge.callAttr(
                                "scan_shared_file", bytes, name, applicationContext.filesDir.absolutePath
                            ).toString()
                            val verdict = JSONObject(scanJson).optString("verdict")
                            if (verdict in setOf("Known threat", "Signature match", "Suspicious", "Needs review")) {
                                highRisk += 1
                            }
                            totalBytes += bytes.size
                            scanned += 1
                        } catch (_: Exception) {
                            skipped += 1
                        }
                    }
                }
            }

            applicationContext.getSharedPreferences("satark_file_guard", Context.MODE_PRIVATE)
                .edit()
                .putLong("last_folder_scan_ms", System.currentTimeMillis())
                .putInt("last_folder_scan_files", scanned)
                .putInt("last_folder_scan_skipped", skipped)
                .putInt("last_folder_scan_alerts", highRisk)
                .apply()

            if (highRisk > 0) notifyThreats(highRisk)

            return Result.success(
                androidx.work.workDataOf(
                    "scanned_files" to scanned,
                    "skipped_files" to skipped,
                    "scanned_bytes" to totalBytes,
                    "alerts" to highRisk,
                    "limit_reached" to hitLimit
                )
            )
        } catch (_: SecurityException) {
            return Result.failure()
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

    private fun notifyThreats(count: Int) {
        if (Build.VERSION.SDK_INT >= 33 &&
            applicationContext.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) return
        val manager = applicationContext.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= 26) {
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "SATARK File Guard alerts", NotificationManager.IMPORTANCE_HIGH)
            )
        }
        val openApp = Intent(applicationContext, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val pending = PendingIntent.getActivity(
            applicationContext, 0, openApp,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val builder = if (Build.VERSION.SDK_INT >= 26) {
            Notification.Builder(applicationContext, CHANNEL_ID)
        } else {
            Notification.Builder(applicationContext)
        }
        val notification = builder
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle("SATARK found files needing review")
            .setContentText(count.toString() + " file(s) matched a local warning rule. Open File Guard to review.")
            .setContentIntent(pending)
            .setAutoCancel(true)
            .build()
        manager.notify(NOTIFICATION_ID, notification)
    }

    companion object {
        const val KEY_TREE_URI = "tree_uri"
        const val UNIQUE_PERIODIC_NAME = "satark-file-guard-daily"
        const val UNIQUE_FREQUENT_NAME = "satark-file-guard-frequent"
        private const val MAX_FILES = 1000
        private const val MAX_DEPTH = 8
        private const val MAX_FILE_BYTES = 64L * 1024L * 1024L
        private const val MAX_TOTAL_BYTES = 512L * 1024L * 1024L
        private const val CHANNEL_ID = "satark-file-guard-alerts"
        private const val NOTIFICATION_ID = 4601
    }
}
