package com.satark.mobile

import android.app.Activity
import android.app.AlertDialog
import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.OpenableColumns
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.workDataOf
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class MainActivity : Activity() {
    private val executor = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())
    private lateinit var status: TextView
    private lateinit var results: TextView
    private lateinit var datasetSource: EditText
    private val maxBytes = 64L * 1024L * 1024L
    private val prefs by lazy { getSharedPreferences("satark_file_guard", MODE_PRIVATE) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ensurePython()
        buildScreen()
        handleIncomingIntent(intent)
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQUEST_NOTIFICATIONS)
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIncomingIntent(intent)
    }

    private fun ensurePython() {
        if (!Python.isStarted()) Python.start(AndroidPlatform(applicationContext))
    }

    private fun buildScreen() {
        val scroll = ScrollView(this)
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(36, 42, 36, 36)
            setBackgroundColor(android.graphics.Color.rgb(10, 17, 31))
        }
        content.addView(text("SATARK", 14f, 0xFF9B8CFF.toInt(), true))
        content.addView(text("File Guard", 32f, 0xFFF3F5FF.toInt(), true))
        content.addView(text(
            "Private, offline-first file inspection. Files are fingerprinted and checked locally; document text is not extracted and files are never executed.",
            15f, 0xFFB8C2D8.toInt(), false
        ))
        status = text("LOCAL ENGINE READY · NO NETWORK LOOKUPS", 12f, 0xFF78E0C1.toInt(), true)
        if (!prefs.getString(KEY_TREE_URI, null).isNullOrBlank()) {
            val lastScan = prefs.getLong("last_folder_scan_ms", 0L)
            val lastCount = prefs.getInt("last_folder_scan_files", 0)
            status.text = if (lastScan > 0L) {
                "FOLDER ACCESS GRANTED · LAST SCAN " + java.text.DateFormat.getDateTimeInstance().format(java.util.Date(lastScan)) +
                    " · " + lastCount + " FILES · " + prefs.getInt("last_folder_scan_alerts", 0) + " ALERTS"
            } else {
                "USER-GRANTED FOLDER ACCESS · LOCAL SCANNING AVAILABLE"
            }
        }
        content.addView(status)
        content.addView(actionButton("Choose a file") { chooseFile() })
        content.addView(actionButton("Choose a folder to monitor") { chooseFolder() })
        content.addView(actionButton("Enable frequent background scan (15 min, best-effort)") { enableFrequentScan() })
        content.addView(actionButton("Enable daily background scan") { enableDailyScan() })
        content.addView(actionButton("Scan selected folder now") { enqueueFolderScan() })
        content.addView(actionButton("Stop background scans (keep folder access)") { stopBackgroundScans() })
        datasetSource = EditText(this).apply {
            hint = "Dataset source / snapshot ID"
            setTextColor(0xFFF3F5FF.toInt())
            setHintTextColor(0xFF8D9AB2.toInt())
            setSingleLine(true)
        }
        content.addView(datasetSource)
        content.addView(actionButton("Import historical SHA-256 CSV") { chooseDataset() })
        content.addView(actionButton("View local scan history") { showHistory() })
        content.addView(actionButton("Clear local scan history") { clearHistory() })
        content.addView(actionButton("Clear imported threat dataset") { confirmClearDataset() })
        content.addView(actionButton("Remove folder access and stop scheduled scans") { removeFolderAccess() })
        content.addView(text(
            "ACCESS BOUNDARY\nSATARK can inspect only files you share or locations you explicitly grant through Android's file picker. It cannot read WhatsApp or Telegram private chat databases. Folder scans are best-effort background work, not continuous 24/7 surveillance.",
            13f, 0xFFFFD28A.toInt(), false
        ))
        content.addView(text("LATEST SCAN RESULTS", 12f, 0xFF9B8CFF.toInt(), true))
        results = text("Share a file from WhatsApp or Telegram, or select one above. The scan runs locally on this device.", 14f, 0xFFE4E9F6.toInt(), false)
        content.addView(results)
        scroll.addView(content)
        setContentView(scroll)
    }

    private fun text(value: String, size: Float, color: Int, bold: Boolean): TextView =
        TextView(this).apply {
            text = value
            textSize = size
            setTextColor(color)
            if (bold) setTypeface(typeface, android.graphics.Typeface.BOLD)
            setPadding(0, 10, 0, 14)
        }

    private fun actionButton(label: String, action: () -> Unit): Button =
        Button(this).apply {
            text = label
            isAllCaps = false
            setTextColor(0xFF0A111F.toInt())
            backgroundTintList = android.content.res.ColorStateList.valueOf(0xFF78E0C1.toInt())
            setOnClickListener { action() }
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, 8, 0, 8) }
        }

    private fun chooseFile() {
        val picker = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
            putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true)
        }
        startActivityForResult(picker, REQUEST_FILES)
    }

    private fun chooseDataset() {
        val source = datasetSource.text.toString().trim()
        if (source.isBlank()) {
            status.text = "ENTER A DATASET SOURCE ID BEFORE IMPORTING"
            return
        }
        val picker = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
            putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true)
        }
        startActivityForResult(picker, REQUEST_DATASET)
    }

    private fun importDatasets(uris: List<Uri>) {
        val source = datasetSource.text.toString().trim()
        status.text = "IMPORTING " + uris.size + " OFFLINE CSV PART(S)…"
        executor.execute {
            var inserted = 0
            var skipped = 0
            var rejected = 0
            var failures = 0
            val summaries = mutableListOf<String>()
            uris.take(100).forEachIndexed { index, uri ->
                try {
                    val bytes = readBounded(uri)
                    val sourceId = (source + ":" + displayName(uri)).take(160)
                    val response = Python.getInstance().getModule("android_bridge")
                        .callAttr("import_csv_snapshot", bytes, sourceId, filesDir.absolutePath).toString()
                    val counts = JSONObject(response).getJSONObject("import")
                    inserted += counts.optInt("inserted")
                    skipped += counts.optInt("skipped")
                    rejected += counts.optInt("rejected")
                    summaries.add(displayName(uri) + " · imported " + counts.optInt("inserted"))
                } catch (error: Exception) {
                    failures += 1
                    summaries.add(displayName(uri) + " · rejected (" + error.javaClass.simpleName + ")")
                }
                mainHandler.post {
                    status.text = "IMPORTING PART " + (index + 1) + " / " + minOf(uris.size, 100)
                }
            }
            mainHandler.post {
                results.text = "EMBER / historical CSV import complete\nInserted: " + inserted +
                    " · Duplicates: " + skipped + " · Invalid rows: " + rejected +
                    " · Failed files: " + failures + "\n\n" + summaries.joinToString("\n")
                status.text = "OFFLINE DATASET IMPORT FINISHED"
            }
        }
    }

    private fun showHistory() {
        executor.execute {
            try {
                val json = Python.getInstance().getModule("android_bridge")
                    .callAttr("scan_history", filesDir.absolutePath).toString()
                val array = org.json.JSONArray(json)
                val lines = (0 until array.length()).map { index ->
                    val item = array.getJSONObject(index)
                    item.optString("scanned_at") + " · " + item.optString("verdict") +
                        " · " + item.optString("filename") + "\nSHA-256: " + item.optString("sha256")
                }
                mainHandler.post {
                    results.text = if (lines.isEmpty()) "No local scan history yet." else lines.joinToString("\n\n")
                    status.text = "LOCAL HISTORY · " + lines.size + " RECORD(S)"
                }
            } catch (error: Exception) {
                mainHandler.post { status.text = "HISTORY UNAVAILABLE · " + error.javaClass.simpleName }
            }
        }
    }

    private fun confirmClearDataset() {
        AlertDialog.Builder(this)
            .setTitle("Clear imported threat dataset?")
            .setMessage("This removes locally imported SHA-256 indicators. It does not delete scan history or any original files.")
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Clear dataset") { _, _ -> clearDataset() }
            .show()
    }

    private fun clearDataset() {
        executor.execute {
            try {
                Python.getInstance().getModule("android_bridge")
                    .callAttr("clear_intelligence", filesDir.absolutePath)
                mainHandler.post {
                    status.text = "LOCAL THREAT DATASET CLEARED"
                    results.text = "Imported hash indicators were removed. The scanner now has no historical hash coverage until a new snapshot is imported."
                }
            } catch (error: Exception) {
                mainHandler.post { status.text = "COULD NOT CLEAR DATASET · " + error.javaClass.simpleName }
            }
        }
    }

    private fun removeFolderAccess() {
        val raw = prefs.getString(KEY_TREE_URI, null)
        if (raw.isNullOrBlank()) {
            status.text = "NO SAVED FOLDER PERMISSION"
            return
        }
        val uri = Uri.parse(raw)
        val flags = prefs.getInt(KEY_TREE_FLAGS, Intent.FLAG_GRANT_READ_URI_PERMISSION)
        try {
            contentResolver.releasePersistableUriPermission(uri, flags)
        } catch (_: SecurityException) {
            // Continue to clear local tracking even if Android already revoked the grant.
        }
        WorkManager.getInstance(this).cancelUniqueWork(FolderScanWorker.UNIQUE_PERIODIC_NAME)
        WorkManager.getInstance(this).cancelUniqueWork(FolderScanWorker.UNIQUE_FREQUENT_NAME)
        WorkManager.getInstance(this).cancelAllWorkByTag(FOLDER_SCAN_TAG)
        prefs.edit().remove(KEY_TREE_URI).remove(KEY_TREE_FLAGS).apply()
        status.text = "FOLDER PERMISSION RELEASED · SCHEDULED SCANS CANCELLED"
    }

    private fun clearHistory() {
        executor.execute {
            try {
                Python.getInstance().getModule("android_bridge")
                    .callAttr("clear_scan_history", filesDir.absolutePath)
                mainHandler.post {
                    results.text = "Local scan history cleared. The historical threat-intelligence database was not changed."
                    status.text = "LOCAL HISTORY CLEARED"
                }
            } catch (error: Exception) {
                mainHandler.post { status.text = "COULD NOT CLEAR HISTORY · " + error.javaClass.simpleName }
            }
        }
    }

    private fun chooseFolder() {
        startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT_TREE), REQUEST_FOLDER)
    }

    private fun handleIncomingIntent(source: Intent?) {
        if (source == null) return
        val clipUris = mutableListOf<Uri>()
        source.clipData?.let { clip ->
            for (index in 0 until clip.itemCount) clipUris.add(clip.getItemAt(index).uri)
        }
        val uris = when (source.action) {
            Intent.ACTION_SEND -> listOfNotNull(source.getParcelableExtra<Uri>(Intent.EXTRA_STREAM), source.data) + clipUris
            Intent.ACTION_SEND_MULTIPLE -> (source.getParcelableArrayListExtra<Uri>(Intent.EXTRA_STREAM)?.toList().orEmpty() + clipUris)
            else -> emptyList()
        }.distinct()
        if (uris.isNotEmpty()) scanUris(uris)
    }

    @Deprecated("Activity result API kept minimal for platform compatibility")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode != RESULT_OK || data == null) return
        when (requestCode) {
            REQUEST_FILES -> {
                val selected = mutableListOf<Uri>()
                data.clipData?.let { clip ->
                    for (i in 0 until clip.itemCount) selected.add(clip.getItemAt(i).uri)
                }
                if (selected.isEmpty()) data.data?.let(selected::add)
                if (selected.isNotEmpty()) scanUris(selected.distinct())
            }
            REQUEST_DATASET -> {
                val selected = mutableListOf<Uri>()
                data.clipData?.let { clip ->
                    for (index in 0 until clip.itemCount) selected.add(clip.getItemAt(index).uri)
                }
                if (selected.isEmpty()) data.data?.let(selected::add)
                if (selected.isNotEmpty()) importDatasets(selected.distinct())
            }
            REQUEST_FOLDER -> {
                val tree = data.data ?: return
                val grantFlags = data.flags and (Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
                try {
                    contentResolver.takePersistableUriPermission(tree, grantFlags)
                    prefs.edit().putString(KEY_TREE_URI, tree.toString()).putInt(KEY_TREE_FLAGS, grantFlags).apply()
                    status.text = "FOLDER ACCESS GRANTED · USER-SELECTED LOCATION ONLY"
                    enqueueFolderScan()
                } catch (_: SecurityException) {
                    status.text = "Folder access could not be persisted. Please choose the folder again."
                }
            }
        }
    }

    private fun scanUris(uris: List<Uri>) {
        status.text = "SCANNING " + uris.size + " FILE(S) LOCALLY…"
        executor.execute {
            val output = mutableListOf<String>()
            uris.take(20).forEach { uri ->
                try {
                    val name = displayName(uri)
                    val bytes = readBounded(uri)
                    val json = Python.getInstance().getModule("android_bridge")
                        .callAttr("scan_shared_file", bytes, name, filesDir.absolutePath).toString()
                    val item = JSONObject(json)
                    val verdict = item.optString("verdict")
                    val safetyNote = if (verdict == "No known threat detected") {
                        "\nNo enabled check matched. This is not proof the file is safe."
                    } else {
                        ""
                    }
                    output.add(
                        verdict + " · " + item.optString("filename") + "\n" +
                        "Type: " + item.optString("detected_type") + " · Risk: " + item.optString("risk_level") +
                        " · Score: " + item.optInt("score") + "\n" +
                        "Size: " + item.optLong("size_bytes") + " bytes\n" +
                        "SHA-256: " + item.optString("sha256") + "\n" +
                        "Evidence signals:\n" + item.optJSONArray("signals")?.toString(2).orEmpty() +
                        "\nAgent trace:\n" + item.optJSONArray("agent_trace")?.toString(2).orEmpty() + safetyNote
                    )
                } catch (error: Exception) {
                    output.add("SCAN INCOMPLETE · " + error.javaClass.simpleName + ". The file was not modified.")
                }
            }
            mainHandler.post {
                results.text = output.joinToString("\n\n──────────────\n\n")
                status.text = "SCAN COMPLETE · " + output.size + " RESULT(S) · LOCAL ONLY"
            }
        }
    }

    private fun displayName(uri: Uri): String {
        contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) {
                val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (index >= 0) return cursor.getString(index) ?: "shared-file"
            }
        }
        return uri.lastPathSegment?.substringAfterLast('/') ?: "shared-file"
    }

    private fun readBounded(uri: Uri): ByteArray {
        val output = ByteArrayOutputStream()
        contentResolver.openInputStream(uri)?.use { input ->
            val buffer = ByteArray(64 * 1024)
            var total = 0L
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                total += count
                if (total > maxBytes) throw IllegalArgumentException("File exceeds 64 MB scan limit")
                output.write(buffer, 0, count)
            }
        } ?: throw IllegalStateException("Android could not open this shared file")
        return output.toByteArray()
    }

    private fun enableFrequentScan() {
        scheduleFolderScan(15, TimeUnit.MINUTES, FolderScanWorker.UNIQUE_FREQUENT_NAME,
            "FREQUENT SCAN SCHEDULED · ANDROID MAY DEFER EXECUTION")
    }

    private fun enableDailyScan() {
        scheduleFolderScan(24, TimeUnit.HOURS, FolderScanWorker.UNIQUE_PERIODIC_NAME,
            "DAILY SCAN SCHEDULED · ANDROID MAY DEFER EXECUTION")
    }

    private fun scheduleFolderScan(interval: Long, unit: TimeUnit, uniqueName: String, statusMessage: String) {
        val uri = prefs.getString(KEY_TREE_URI, null)
        if (uri.isNullOrBlank()) {
            status.text = "CHOOSE A FOLDER FIRST · NO STORAGE IS SCANNED WITHOUT PERMISSION"
            return
        }
        val otherName = if (uniqueName == FolderScanWorker.UNIQUE_FREQUENT_NAME) {
            FolderScanWorker.UNIQUE_PERIODIC_NAME
        } else {
            FolderScanWorker.UNIQUE_FREQUENT_NAME
        }
        WorkManager.getInstance(this).cancelUniqueWork(otherName)
        val request = PeriodicWorkRequestBuilder<FolderScanWorker>(interval, unit)
            .setConstraints(Constraints.Builder().build())
            .build()
        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            uniqueName,
            ExistingPeriodicWorkPolicy.UPDATE,
            request
        )
        status.text = statusMessage
    }

    private fun stopBackgroundScans() {
        WorkManager.getInstance(this).cancelUniqueWork(FolderScanWorker.UNIQUE_PERIODIC_NAME)
        WorkManager.getInstance(this).cancelUniqueWork(FolderScanWorker.UNIQUE_FREQUENT_NAME)
        WorkManager.getInstance(this).cancelAllWorkByTag(FOLDER_SCAN_TAG)
        status.text = if (prefs.getString(KEY_TREE_URI, null).isNullOrBlank()) {
            "BACKGROUND SCANS STOPPED · NO SAVED FOLDER PERMISSION"
        } else {
            "BACKGROUND SCANS STOPPED · FOLDER ACCESS RETAINED"
        }
    }

    private fun enqueueFolderScan() {
        val uri = prefs.getString(KEY_TREE_URI, null)
        if (uri.isNullOrBlank()) {
            status.text = "NO FOLDER GRANTED · CHOOSE A FOLDER FIRST"
            return
        }
        val request = OneTimeWorkRequestBuilder<FolderScanWorker>()
            .setInputData(workDataOf(FolderScanWorker.KEY_TREE_URI to uri))
            .addTag(FOLDER_SCAN_TAG)
            .build()
        WorkManager.getInstance(this).enqueue(request)
        status.text = "FOLDER SCAN QUEUED · ANDROID BACKGROUND SCHEDULER"
    }

    override fun onDestroy() {
        executor.shutdown()
        super.onDestroy()
    }

    companion object {
        private const val REQUEST_FILES = 401
        private const val REQUEST_FOLDER = 402
        private const val REQUEST_DATASET = 403
        private const val REQUEST_NOTIFICATIONS = 404
        private const val KEY_TREE_URI = "granted_tree_uri"
        private const val KEY_TREE_FLAGS = "granted_tree_flags"
        private const val FOLDER_SCAN_TAG = "satark-folder-scan"
    }
}
