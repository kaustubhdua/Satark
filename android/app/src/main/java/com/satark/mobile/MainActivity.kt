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
    private lateinit var datasetStatus: TextView
    private lateinit var lastScanStatus: TextView
    private var pendingExportJson: String? = null
    private val maxBytes = 64L * 1024L * 1024L
    private val prefs by lazy { getSharedPreferences("satark_file_guard", MODE_PRIVATE) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ensurePython()
        buildScreen()
        refreshDatasetStats()
        handleIncomingIntent(intent)
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQUEST_NOTIFICATIONS)
        }
    }

    override fun onResume() {
        super.onResume()
        if (::datasetStatus.isInitialized && ::lastScanStatus.isInitialized) {
            refreshDatasetStats()
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
        val scroll = ScrollView(this).apply { clipToPadding = false }
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(28), dp(20), dp(32))
            setBackgroundColor(android.graphics.Color.rgb(8, 14, 27))
        }

        val brand = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = android.view.Gravity.CENTER_VERTICAL
        }
        brand.addView(text("◈", 25f, 0xFF78E0C1.toInt(), true))
        val brandName = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        brandName.addView(text("SATARK", 15f, 0xFFF3F5FF.toInt(), true))
        brandName.addView(text("FILE GUARD · OFFLINE", 10f, 0xFF8D9AB2.toInt(), true))
        brand.addView(brandName)
        val localTag = text("LOCAL ONLY", 10f, 0xFF78E0C1.toInt(), true).apply {
            setPadding(dp(10), dp(7), dp(10), dp(7))
            background = rounded(0xFF12352F.toInt(), 0xFF28675B.toInt())
        }
        brand.addView(localTag, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { gravity = android.view.Gravity.CENTER_VERTICAL; leftMargin = dp(12) })
        content.addView(brand)

        content.addView(text("Your files.\nChecked locally.", 34f, 0xFFF3F5FF.toInt(), true))
        content.addView(text(
            "Share an attachment or choose a folder. SATARK fingerprints files on this device without extracting document text or sending samples anywhere.",
            14f, 0xFFAFBCD2.toInt(), false
        ))

        status = text("LOCAL ENGINE READY · NO NETWORK LOOKUPS", 11f, 0xFF78E0C1.toInt(), true).apply {
            setPadding(dp(14), dp(12), dp(14), dp(12))
            background = rounded(0xFF102A2A.toInt(), 0xFF28564F.toInt())
        }
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
        content.addView(panel(status))

        content.addView(sectionTitle("LAST LOCAL SCAN"))
        lastScanStatus = text("No scan history recorded on this device yet.", 12f, 0xFFAFBCD2.toInt(), false)
        content.addView(panel(lastScanStatus))

        content.addView(sectionTitle("PROTECT YOUR FILES"))
        content.addView(actionButton("Scan a file", { chooseFile() }, true))
        content.addView(actionButton("Choose a folder to monitor", { chooseFolder() }))
        content.addView(actionButton("Scan selected folder now", { enqueueFolderScan() }))
        content.addView(actionButton("Enable frequent scan · 15 min minimum", { enableFrequentScan() }))
        content.addView(actionButton("Enable daily background scan", { enableDailyScan() }))
        content.addView(actionButton("Stop background scans", { stopBackgroundScans() }))

        content.addView(sectionTitle("HISTORICAL THREAT INTELLIGENCE"))
        content.addView(text(
            "Frozen local snapshot · no live feed · no automatic updates",
            12f, 0xFFAFBCD2.toInt(), false
        ))
        datasetSource = EditText(this).apply {
            hint = "Dataset source / snapshot ID"
            setTextColor(0xFFF3F5FF.toInt())
            setHintTextColor(0xFF8D9AB2.toInt())
            setSingleLine(true)
            textSize = 14f
            setPadding(dp(14), dp(12), dp(14), dp(12))
            background = rounded(0xFF111D31.toInt(), 0xFF2B3A54.toInt())
        }
        content.addView(datasetSource, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { bottomMargin = dp(10) })
        datasetStatus = text("HISTORICAL DATASET · CHECKING LOCAL DATABASE…", 12f, 0xFF78E0C1.toInt(), true)
        content.addView(panel(datasetStatus))
        content.addView(actionButton("Import historical SHA-256 CSV parts", { chooseDataset() }))
        content.addView(actionButton("View dataset coverage", { showDatasetStats() }))
        content.addView(actionButton("Clear imported threat dataset", { confirmClearDataset() }))

        content.addView(sectionTitle("RECENT ACTIVITY"))
        results = text(
            "No scan selected yet. Share a file from WhatsApp or Telegram, or choose a file above. Results and history stay on this device.",
            13f, 0xFFE4E9F6.toInt(), false
        )
        content.addView(panel(results))
        content.addView(actionButton("View local scan history", { showHistory() }))
        content.addView(actionButton("Export detailed evidence report (JSON)", { exportEvidenceReport() }))
        content.addView(actionButton("Clear local scan history", { clearHistory() }))

        content.addView(sectionTitle("PRIVACY BY DESIGN"))
        content.addView(panel(text(
            "SATARK can inspect only files you share or locations you explicitly grant through Android's file picker. It cannot read WhatsApp or Telegram private chat databases. Background scans are best-effort and are not continuous 24/7 surveillance. Original files are never modified or deleted.",
            12f, 0xFFFFD28A.toInt(), false
        )))
        content.addView(text(
            "A no-match result means no enabled local check recognised the file. It is not a guarantee of safety.",
            11f, 0xFF8D9AB2.toInt(), false
        ))

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

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    private fun rounded(fill: Int, stroke: Int): android.graphics.drawable.GradientDrawable =
        android.graphics.drawable.GradientDrawable().apply {
            cornerRadius = dp(16).toFloat()
            setColor(fill)
            setStroke(dp(1), stroke)
        }

    private fun panel(child: TextView): LinearLayout =
        LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(15), dp(12), dp(15), dp(12))
            background = rounded(0xFF111D31.toInt(), 0xFF24334B.toInt())
            addView(child)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(14) }
        }

    private fun sectionTitle(label: String): TextView =
        text(label, 11f, 0xFF9B8CFF.toInt(), true).apply {
            setPadding(0, dp(14), 0, dp(8))
        }

    private fun actionButton(label: String, action: () -> Unit, primary: Boolean = false): Button =
        Button(this).apply {
            text = label
            isAllCaps = false
            textSize = 14f
            setTextColor(if (primary) 0xFF08151A.toInt() else 0xFFEAF1FF.toInt())
            background = if (primary) {
                rounded(0xFF78E0C1.toInt(), 0xFF78E0C1.toInt())
            } else {
                rounded(0xFF18263D.toInt(), 0xFF30415D.toInt())
            }
            setPadding(dp(14), dp(7), dp(14), dp(7))
            minHeight = dp(52)
            setOnClickListener { action() }
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, dp(4), 0, dp(7)) }
        }

    private fun exportEvidenceReport() {
        status.text = "PREPARING LOCAL EVIDENCE REPORT…"
        executor.execute {
            try {
                val report = Python.getInstance().getModule("android_bridge")
                    .callAttr("export_scan_report", filesDir.absolutePath).toString()
                mainHandler.post {
                    pendingExportJson = report
                    val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                        addCategory(Intent.CATEGORY_OPENABLE)
                        type = "application/json"
                        putExtra(Intent.EXTRA_TITLE, "satark-evidence-report-" + System.currentTimeMillis() + ".json")
                    }
                    startActivityForResult(intent, REQUEST_EXPORT)
                }
            } catch (error: Exception) {
                mainHandler.post { status.text = "REPORT PREPARATION FAILED · " + error.javaClass.simpleName }
            }
        }
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
            val stats = try {
                JSONObject(Python.getInstance().getModule("android_bridge")
                    .callAttr("scan_stats", filesDir.absolutePath).toString())
            } catch (_: Exception) {
                JSONObject()
            }
            mainHandler.post {
                results.text = "EMBER / historical CSV import complete\nInserted: " + inserted +
                    " · Duplicates: " + skipped + " · Invalid rows: " + rejected +
                    " · Failed files: " + failures + "\n\nCurrent local dataset: " +
                    stats.optInt("total") + " hashes (" + stats.optInt("malicious") +
                    " malicious · " + stats.optInt("benign") + " benign)\n\n" +
                    summaries.joinToString("\n")
                datasetStatus.text = "HISTORICAL DATASET · " + stats.optInt("total") +
                    " HASHES · " + stats.optInt("malicious") + " MALICIOUS · " +
                    stats.optInt("benign") + " BENIGN"
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
                val lines = (0 until minOf(array.length(), 20)).map { index ->
                    val item = array.getJSONObject(index)
                    val evidence = item.optJSONObject("evidence_report")
                    val signals = item.optJSONArray("signals")?.toString(2).orEmpty()
                    val trace = evidence?.optJSONArray("agent_trace")?.toString(2).orEmpty()
                    item.optString("scanned_at") + " · " + item.optString("verdict") +
                        " · " + item.optString("filename") + "\nSHA-256: " + item.optString("sha256") +
                        "\nSignals:\n" + signals + "\nSpecialist evidence:\n" + trace
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

    private fun refreshDatasetStats() {
        executor.execute {
            try {
                val bridge = Python.getInstance().getModule("android_bridge")
                val stats = JSONObject(bridge.callAttr("scan_stats", filesDir.absolutePath).toString())
                val history = org.json.JSONArray(bridge.callAttr("scan_history", filesDir.absolutePath).toString())
                val latest = if (history.length() > 0) history.getJSONObject(0) else null
                mainHandler.post {
                    datasetStatus.text = "HISTORICAL DATASET · " + stats.optInt("total") +
                        " HASHES · " + stats.optInt("malicious") + " MALICIOUS · " +
                        stats.optInt("benign") + " BENIGN"
                    lastScanStatus.text = if (latest == null) {
                        "No scan history recorded on this device yet."
                    } else {
                        latest.optString("scanned_at") + " · " + latest.optString("filename") +
                            " · " + latest.optString("verdict") + " · SHA-256 " + latest.optString("sha256")
                    }
                }
            } catch (_: Exception) {
                mainHandler.post { datasetStatus.text = "HISTORICAL DATASET STATUS UNAVAILABLE" }
            }
        }
    }

    private fun showDatasetStats() {
        executor.execute {
            try {
                val stats = JSONObject(Python.getInstance().getModule("android_bridge")
                    .callAttr("scan_stats", filesDir.absolutePath).toString())
                val total = stats.optInt("total")
                val message = "Local historical indicators: " + total +
                    "\nMalicious labels: " + stats.optInt("malicious") +
                    "\nBenign labels: " + stats.optInt("benign") +
                    "\n\nThe database is frozen between explicit imports. A no-match result is not proof that a file is safe."
                mainHandler.post {
                    results.text = message
                    status.text = if (total == 0) {
                        "NO HISTORICAL HASH SNAPSHOT IMPORTED"
                    } else {
                        "LOCAL HISTORICAL INTELLIGENCE READY"
                    }
                }
            } catch (error: Exception) {
                mainHandler.post { status.text = "DATASET STATUS UNAVAILABLE · " + error.javaClass.simpleName }
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
                    datasetStatus.text = "HISTORICAL DATASET · 0 HASHES · IMPORT A SNAPSHOT TO ENABLE HASH MATCHING"
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
        WorkManager.getInstance(this).cancelUniqueWork(IMMEDIATE_FOLDER_SCAN_NAME)
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
            REQUEST_EXPORT -> {
                val destination = data.data ?: return
                val report = pendingExportJson ?: return
                executor.execute {
                    try {
                        contentResolver.openOutputStream(destination, "wt")?.use { output ->
                            output.write(report.toByteArray(Charsets.UTF_8))
                        } ?: throw IllegalStateException("Android could not open the report destination")
                        pendingExportJson = null
                        mainHandler.post { status.text = "EVIDENCE REPORT EXPORTED · METADATA ONLY · LOCAL" }
                    } catch (error: Exception) {
                        mainHandler.post { status.text = "REPORT EXPORT FAILED · " + error.javaClass.simpleName }
                    }
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
                refreshDatasetStats()
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
        WorkManager.getInstance(this).enqueueUniqueWork(
            IMMEDIATE_FOLDER_SCAN_NAME,
            androidx.work.ExistingWorkPolicy.REPLACE,
            request
        )
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
        private const val REQUEST_EXPORT = 405
        private const val KEY_TREE_URI = "granted_tree_uri"
        private const val KEY_TREE_FLAGS = "granted_tree_flags"
        private const val FOLDER_SCAN_TAG = "satark-folder-scan"
        private const val IMMEDIATE_FOLDER_SCAN_NAME = "satark-file-guard-immediate-folder-scan"
    }
}
