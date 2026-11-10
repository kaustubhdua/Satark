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
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkInfo
import androidx.work.workDataOf
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class MainActivity : Activity() {
    private val executor = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())
    private lateinit var status: TextView
    private lateinit var results: TextView
    private lateinit var datasetSource: EditText
    private lateinit var datasetStatus: TextView
    private var pendingExportJson: String? = null
    private var starterSnapshotError: String? = null
    private val maxBytes = 64L * 1024L * 1024L
    private val prefs by lazy { getSharedPreferences("satark_file_guard", MODE_PRIVATE) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ScanTempFiles.cleanup(cacheDir)
        try {
            installBundledSnapshotIfMissing()
        } catch (error: Exception) {
            starterSnapshotError = error.javaClass.simpleName
        }
        WindowCompat.setDecorFitsSystemWindows(window, false)
        window.statusBarColor = android.graphics.Color.TRANSPARENT
        window.navigationBarColor = android.graphics.Color.TRANSPARENT
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

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIncomingIntent(intent)
    }

    private fun ensurePython() {
        if (!Python.isStarted()) Python.start(AndroidPlatform(applicationContext))
    }

    private fun buildScreen() {
        val scroll = ScrollView(this).apply {
            isFillViewport = true

            setBackgroundColor(0xFF080F1D.toInt())
        }
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(24), dp(20), dp(32))
            setBackgroundColor(0xFF080F1D.toInt())
        }

        content.addView(text("SATARK  /  ON-DEVICE SECURITY", 11f, 0xFF9B8CFF.toInt(), true))
        content.addView(text("File Guard", 34f, 0xFFF3F5FF.toInt(), true))
        content.addView(text(
            "Private file inspection. Fingerprints and signatures stay on this device.",
            15f, 0xFFB8C2D8.toInt(), false
        ))

        val hero = panel()
        hero.addView(text("LOCAL ENGINE", 11f, 0xFF78E0C1.toInt(), true))
        hero.addView(text("Your files. Checked locally.", 21f, 0xFFF3F5FF.toInt(), true))
        hero.addView(text(
            "No cloud scan, no account, no remote reputation lookup. Share an attachment to SATARK or choose it below.",
            13f, 0xFFB8C2D8.toInt(), false
        ))
        status = text("READY · OFFLINE SCANNING", 12f, 0xFF78E0C1.toInt(), true)
        val foregroundScanAt = prefs.getLong("last_scan_ms", 0L)
        val folderScanAt = prefs.getLong("last_folder_scan_ms", 0L)
        val lastScanAt = maxOf(foregroundScanAt, folderScanAt)
        if (lastScanAt > 0L) {
            val folderWasLatest = folderScanAt >= foregroundScanAt
            val lastCount = if (folderWasLatest) prefs.getInt("last_folder_scan_files", 0)
                else prefs.getInt("last_scan_files", 0)

        } else if (!prefs.getString(KEY_TREE_URI, null).isNullOrBlank()) {
            status.text = "FOLDER ACCESS GRANTED · READY TO SCAN"
        }
        hero.addView(status)
        content.addView(hero, panelParams())

        val scanPanel = panel()
        scanPanel.addView(sectionTitle("Quick scan"))
        scanPanel.addView(text("Inspect one or more files shared from WhatsApp, Telegram, your browser or file manager.", 13f, 0xFFB8C2D8.toInt(), false))
        scanPanel.addView(primaryActionButton("Choose files to scan") { chooseFile() })
        content.addView(scanPanel, panelParams())

        val folderPanel = panel()
        folderPanel.addView(sectionTitle("Folder protection"))
        folderPanel.addView(text("Choose a folder you control. Scheduled rescans are best-effort and may be deferred by Android.", 13f, 0xFFB8C2D8.toInt(), false))
        folderPanel.addView(primaryActionButton("Choose a folder to monitor") { chooseFolder() })
        folderPanel.addView(actionButton("Scan selected folder now") { enqueueFolderScan() })
        folderPanel.addView(actionButton("Frequent scan · every 15 min (best-effort)") { enableFrequentScan() })
        folderPanel.addView(actionButton("Daily background scan") { enableDailyScan() })
        folderPanel.addView(actionButton("Stop background scans") { stopBackgroundScans() })
        content.addView(folderPanel, panelParams())

        val intelligencePanel = panel()
        intelligencePanel.addView(sectionTitle("Historical intelligence"))
        intelligencePanel.addView(text("Import a fixed, provenance-labelled snapshot. No dataset refresh happens during scans.", 13f, 0xFFB8C2D8.toInt(), false))
        datasetSource = EditText(this).apply {
            hint = "Dataset source / snapshot ID"
            setText("EMBER2024-2024-12-14")
            setTextColor(0xFFF3F5FF.toInt())
            setHintTextColor(0xFF8D9AB2.toInt())
            setSingleLine(true)
            setPadding(dp(12), dp(10), dp(12), dp(10))
            backgroundTintList = android.content.res.ColorStateList.valueOf(0xFF596A8A.toInt())
        }
        intelligencePanel.addView(datasetSource, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { topMargin = dp(8) })
        datasetStatus = text("HISTORICAL DATASET · CHECKING LOCAL DATABASE…", 12f, 0xFF78E0C1.toInt(), true)
        intelligencePanel.addView(datasetStatus)

        content.addView(intelligencePanel, panelParams())

        val historyPanel = panel()
        historyPanel.addView(sectionTitle("Scan history"))
        historyPanel.addView(text("Review previous local scans and their saved evidence reports.", 13f, 0xFFB8C2D8.toInt(), false))
        historyPanel.addView(primaryActionButton("View scan history and evidence") { showHistory() })

        historyPanel.addView(actionButton("Clear local scan history") { clearHistory() })
        content.addView(historyPanel, panelParams())

        val privacyPanel = panel()
        privacyPanel.addView(sectionTitle("Privacy and access boundary"))
        privacyPanel.addView(text(
            "SATARK reads raw bytes only to calculate SHA-256 and inspect bounded signatures. It does not extract document text, read messages or chat databases, OCR, preview, unpack or execute files. Android allows access only to files you share or folders you explicitly grant; private WhatsApp and Telegram storage remains inaccessible.",
            13f, 0xFFB8C2D8.toInt(), false
        ))
        privacyPanel.addView(text(
            "WorkManager is not continuous 24/7 protection. A no-match result is not proof that a file is safe.",
            12f, 0xFFFFD28A.toInt(), true
        ))
        privacyPanel.addView(actionButton("Remove folder access and stop scheduled scans") { removeFolderAccess() })
        content.addView(privacyPanel, panelParams())

        val resultsPanel = panel()
        resultsPanel.addView(sectionTitle("Latest scan results"))
        results = text("No scans yet. Share a file to SATARK or choose files above. Results and evidence are stored locally.", 13f, 0xFFE4E9F6.toInt(), false)
        resultsPanel.addView(results)
        content.addView(resultsPanel, panelParams())


        scroll.addView(content)
        setContentView(scroll)
        ViewCompat.requestApplyInsets(scroll)
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    private fun panel(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(18), dp(16), dp(18), dp(16))
        background = android.graphics.drawable.GradientDrawable().apply {
            setColor(0xFF121E32.toInt())
            cornerRadius = dp(20).toFloat()
            setStroke(dp(1), 0xFF263854.toInt())
        }
    }


    private fun panelParams() = LinearLayout.LayoutParams(
        LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT
    ).apply { setMargins(0, dp(10), 0, dp(4)) }

    private fun sectionTitle(value: String): TextView =
        text(value, 17f, 0xFFF3F5FF.toInt(), true)

    private fun text(value: String, size: Float, color: Int, bold: Boolean): TextView =
        TextView(this).apply {
            text = value
            textSize = size
            setTextColor(color)
            if (bold) setTypeface(typeface, android.graphics.Typeface.BOLD)
            setLineSpacing(dp(2).toFloat(), 1.04f)
            setPadding(0, dp(5), 0, dp(8))
        }

    private fun actionButton(label: String, action: () -> Unit): Button =
        Button(this).apply {
            text = label
            isAllCaps = false
            textSize = 13f
            setTextColor(0xFFDCE6F8.toInt())
            backgroundTintList = android.content.res.ColorStateList.valueOf(0xFF253650.toInt())
            setOnClickListener { action() }
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, dp(5), 0, dp(5)) }
        }

    private fun primaryActionButton(label: String, action: () -> Unit): Button =
        Button(this).apply {
            text = label
            isAllCaps = false
            textSize = 14f
            setTypeface(typeface, android.graphics.Typeface.BOLD)
            setTextColor(0xFF081521.toInt())
            backgroundTintList = android.content.res.ColorStateList.valueOf(0xFF78E0C1.toInt())
            setOnClickListener { action() }
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, dp(7), 0, dp(7)) }
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
        val manifests = uris.filter { displayName(it).lowercase().endsWith("_manifest.json") }

        val csvUris = uris.filter { displayName(it).lowercase().endsWith(".csv") }
        if (csvUris.isEmpty()) {
            status.text = "SELECT ONE OR MORE CSV PARTS"
            return
        }
        if (csvUris.size > 256) {
            status.text = "IMPORT IN BATCHES OF UP TO 256 CSV PARTS"
            results.text = "Too many CSV parts were selected. Split the snapshot into batches of at most 256 parts; keep the same source ID and manifest for each batch."
            return
        }

            status.text = "SELECT ONLY ONE DATASET MANIFEST"
            return
        }
        status.text = "VERIFYING OFFLINE DATASET MANIFEST…"
        executor.execute {
            var manifestParts: Map<String, String> = emptyMap()
            var manifestError: String? = null
            if (manifests.size == 1) {
                try {
                    val manifestBytes = readBounded(manifests.first())
                    val manifest = JSONObject(String(manifestBytes, Charsets.UTF_8))

                    val parsed = mutableMapOf<String, String>()
                    for (index in 0 until parts.length()) {
                        val part = parts.getJSONObject(index)
                        val filename = part.optString("file")
                        val digest = part.optString("sha256").lowercase()
                        if (filename.isBlank() || !digest.matches(Regex("^[a-f0-9]{64}$"))) {
                            throw IllegalArgumentException("Manifest contains an invalid part entry")
                        }
                        if (parsed.put(filename, digest) != null) {
                            throw IllegalArgumentException("Manifest contains duplicate filenames")
                        }
                    }
                    manifestParts = parsed
                } catch (error: Exception) {
                    manifestError = error.javaClass.simpleName
                }
            }

            var inserted = 0
            var skipped = 0
            var rejected = 0
            var failures = 0
            var checksumVerified = 0
            val summaries = mutableListOf<String>()
            if (manifestError != null) {
                failures = csvUris.size
                summaries.add("Manifest rejected · " + manifestError)
            } else {
                csvUris.forEachIndexed { index, uri ->
                    val name = displayName(uri)
                    try {
                        val expected = if (manifests.isNotEmpty()) {
                            manifestParts[name] ?: throw IllegalArgumentException("CSV part is not listed in the selected manifest")
                        } else {
                            ""
                        }
                        val bytes = readBounded(uri)
                        val sourceId = (source + ":" + name).take(160)
                        val response = Python.getInstance().getModule("android_bridge")
                            .callAttr("import_csv_snapshot", bytes, sourceId, filesDir.absolutePath, expected).toString()
                        val payload = JSONObject(response)
                        val counts = payload.getJSONObject("import")
                        inserted += counts.optInt("inserted")
                        skipped += counts.optInt("skipped")
                        rejected += counts.optInt("rejected")
                        if (payload.optBoolean("checksum_verified")) checksumVerified += 1
                        summaries.add(name + " · imported " + counts.optInt("inserted") +
                            if (payload.optBoolean("checksum_verified")) " · checksum verified" else " · checksum not supplied")
                    } catch (error: Exception) {
                        failures += 1
                        summaries.add(name + " · rejected (" + error.javaClass.simpleName + ")")
                    }
                    mainHandler.post {
                        status.text = "IMPORTING PART " + (index + 1) + " / " + csvUris.size
                    }
                }
            }
            val stats = try {
                JSONObject(Python.getInstance().getModule("android_bridge")
                    .callAttr("scan_stats", filesDir.absolutePath).toString())
            } catch (_: Exception) {
                JSONObject()
            }
            mainHandler.post {
                results.text = "Historical CSV import complete\nInserted: " + inserted +
                    " · Duplicates: " + skipped + " · Invalid rows: " + rejected +
                    " · Failed files: " + failures + "\nChecksum-verified parts: " + checksumVerified +
                    "\n\nCurrent local dataset: " + stats.optInt("total") + " hashes (" +
                    stats.optInt("malicious") + " malicious · " + stats.optInt("benign") +
                    " benign)\n\n" + summaries.joinToString("\n")
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
                val lines = (0 until array.length()).map { index ->
                    val item = array.getJSONObject(index)
                    val report = item.optJSONObject("report")

                    val assessment = report?.optJSONObject("assessment")
                    val evidence = report?.optJSONObject("evidence")
                    val trace = evidence?.optJSONArray("agent_trace")?.toString(2).orEmpty()
                    val snapshot = report?.optJSONObject("snapshot")
                    val source = evidence?.optJSONObject("intelligence_match")?.optString("source").orEmpty()
                    item.optString("scanned_at") + " · " + item.optString("verdict") +
                        " · " + item.optString("filename") + "\nSHA-256: " + item.optString("sha256") +
                        "\nEvidence report: " + report?.optString("report_sha256").orEmpty() +

                        "\nAssessment: " + assessment?.optString("interpretation").orEmpty() +
                        "\nSnapshot: " + snapshot?.optInt("total") + " hashes · " +
                        snapshot?.optInt("malicious") + " malicious · " + snapshot?.optInt("benign") + " benign" +
                        "\nMatched source: " + source +
                        "\nAgent trace:\n" + trace
                }
                mainHandler.post {
                    results.text = if (lines.isEmpty()) "No local scan history yet." else lines.joinToString("\n\n──────────────\n\n")
                    status.text = "LOCAL HISTORY · " + lines.size + " RECORD(S) · EVIDENCE REPORTS SAVED"
                }
            } catch (error: Exception) {
                mainHandler.post { status.text = "HISTORY UNAVAILABLE · " + error.javaClass.simpleName }
            }
        }
    }

    private fun exportLatestEvidenceReport() {
        executor.execute {
            try {
                val history = org.json.JSONArray(
                    Python.getInstance().getModule("android_bridge")
                        .callAttr("scan_history", filesDir.absolutePath).toString()
                )
                if (history.length() == 0) {
                    mainHandler.post { status.text = "NO EVIDENCE REPORT TO EXPORT YET" }
                    return@execute
                }
                val latest = history.getJSONObject(0)
                val report = latest.optJSONObject("report")
                    ?: throw IllegalStateException("Latest scan has no evidence report")
                if (report.optString("report_sha256").isBlank()) {
                    throw IllegalStateException("Latest scan has no verified evidence report")
                }
                val payload = report.toString(2)
                val digest = report.optString("sha256").take(12).ifBlank { "latest" }
                mainHandler.post {
                    pendingExportJson = payload
                    val picker = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                        addCategory(Intent.CATEGORY_OPENABLE)
                        type = "application/json"
                        putExtra(Intent.EXTRA_TITLE, "satark-evidence-$digest.json")
                    }
                    startActivityForResult(picker, REQUEST_EXPORT)
                }
            } catch (error: Exception) {
                mainHandler.post { status.text = "REPORT EXPORT UNAVAILABLE · " + error.javaClass.simpleName }
            }
        }
    }

    private fun verifyAuditChain() {
        executor.execute {
            try {
                val payload = JSONObject(
                    Python.getInstance().getModule("android_bridge")
                        .callAttr("verify_scan_audit", filesDir.absolutePath).toString()
                )
                val valid = payload.optBoolean("valid")
                val complete = payload.optBoolean("complete", true)
                val entries = payload.optInt("entries")
                val reports = payload.optInt("verified_reports")
                val unlinked = payload.optInt("unlinked_history_records")
                val head = payload.optString("head_sha256")
                val reason = payload.optString("reason")
                mainHandler.post {
                    results.text = if (valid) {
                        "LOCAL AUDIT CHAIN VERIFIED\nEntries: " + entries +
                            " · Evidence reports verified: " + reports +
                            " · Legacy records not linked: " + unlinked +
                            "\nCurrent chain head: " + head +
                            "\n\nThis detects edits or reordering within the retained local chain. It is not a digital signature or remote proof of authenticity."
                    } else {
                        "LOCAL AUDIT CHAIN VERIFICATION FAILED\nFailed sequence: " +
                            payload.optInt("failed_sequence") + "\nReason: " + reason +
                            "\n\nPreserve this database and investigate before clearing history."
                    }
                    status.text = when {
                        !valid -> "WARNING · LOCAL EVIDENCE CHAIN INTEGRITY FAILURE"
                        !complete -> "AUDIT CHAIN VALID · " + unlinked + " LEGACY RECORD(S) UNLINKED"
                        else -> "LOCAL EVIDENCE CHAIN INTACT · " + entries + " RECORD(S)"
                    }
                }
            } catch (error: Exception) {
                mainHandler.post { status.text = "AUDIT VERIFICATION UNAVAILABLE · " + error.javaClass.simpleName }
            }
        }
    }

    private fun copyBundledSnapshotTo(destination: File): String? {
        if (destination.exists()) return null
        val metadataText = try {
            assets.open("ember2024-starter.json").bufferedReader(Charsets.UTF_8).use { it.readText() }
        } catch (_: java.io.FileNotFoundException) {
            return null
        }
        val metadata = JSONObject(metadataText)
        val pinnedRevision = "8cc201a3d2a1cb2957123eb5ad996d5a3178bbcc"
        val expectedSha256 = metadata.optString("database_sha256").lowercase()
        val expectedBytes = metadata.optLong("database_bytes", -1L)
        if (metadata.optString("dataset") != "EMBER2024" ||
            metadata.optString("dataset_revision") != pinnedRevision ||
            metadata.optBoolean("contains_file_binaries", true) ||
            !metadata.optBoolean("contains_only_sha256_labels_and_metadata", false) ||
            !expectedSha256.matches(Regex("^[a-f0-9]{64}$")) ||
            expectedBytes <= 0L
        ) {
            throw IllegalStateException("Bundled historical snapshot metadata is invalid")
        }
        destination.parentFile?.mkdirs()
        val temporary = File(destination.parentFile, destination.name + ".installing")
        temporary.delete()
        try {
            val digest = MessageDigest.getInstance("SHA-256")
            var copiedBytes = 0L
            assets.open("ember2024-starter.sqlite3").use { input ->
                temporary.outputStream().use { output ->
                    val buffer = ByteArray(64 * 1024)
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        digest.update(buffer, 0, count)
                        output.write(buffer, 0, count)
                        copiedBytes += count
                    }
                }
            }
            val actualSha256 = digest.digest().joinToString("") {
                "%02x".format(it.toInt() and 0xff)
            }
            if (copiedBytes != expectedBytes || actualSha256 != expectedSha256) {
                throw IllegalStateException("Bundled historical snapshot checksum mismatch")
            }
            if (!temporary.renameTo(destination)) {
                throw IllegalStateException("Could not install bundled historical snapshot")
            }
            return metadata.optString("source_id")
        } catch (error: Exception) {
            temporary.delete()
            throw error
        }
    }

    private fun installBundledSnapshotIfMissing(): Boolean {
        val destination = File(filesDir, "file_guard_intelligence.sqlite3")
        if (destination.exists()) return false
        val sourceId = copyBundledSnapshotTo(destination) ?: return false
        prefs.edit().putString("bundled_snapshot_id", sourceId).apply()
        return true
    }

    private fun restoreBundledSnapshot() {
        AlertDialog.Builder(this)
            .setTitle("Restore historical starter snapshot?")
            .setMessage("This replaces the local threat-intelligence database with the APK training snapshot bundled in this build. Additional imported datasets will be removed. Scan history is preserved.")
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Restore") { _, _ ->
                stopBackgroundScans()
                executor.execute {
                    try {
                        val workInfos = WorkManager.getInstance(this)
                            .getWorkInfosByTag(FOLDER_SCAN_TAG).get(15, TimeUnit.SECONDS)
                        if (workInfos.any { it.state == WorkInfo.State.RUNNING }) {
                            throw IllegalStateException("Wait for the current folder scan to stop, then restore again")
                        }
                        val database = File(filesDir, "file_guard_intelligence.sqlite3")
                        val staged = File(filesDir, "file_guard_intelligence.sqlite3.restore")
                        val backup = File(filesDir, "file_guard_intelligence.sqlite3.backup")
                        staged.delete()
                        backup.delete()
                        val sourceId = copyBundledSnapshotTo(staged)
                            ?: throw IllegalStateException("This build does not contain a valid bundled starter snapshot")
                        if (database.exists() && !database.renameTo(backup)) {
                            staged.delete()
                            throw IllegalStateException("Could not safely stage the current intelligence database")
                        }
                        if (!staged.renameTo(database)) {
                            if (backup.exists()) backup.renameTo(database)
                            throw IllegalStateException("Could not activate the restored starter database")
                        }
                        backup.delete()
                        prefs.edit().putString("bundled_snapshot_id", sourceId).apply()
                        starterSnapshotError = null
                        val stats = JSONObject(
                            Python.getInstance().getModule("android_bridge")
                                .callAttr("scan_stats", filesDir.absolutePath).toString()
                        )
                        mainHandler.post {
                            datasetStatus.text = "BUNDLED EMBER2024 RESTORED · " +
                                stats.optInt("total") + " HASHES · " +
                                stats.optInt("malicious") + " MALICIOUS · " +
                                stats.optInt("benign") + " BENIGN"
                            status.text = "HISTORICAL OFFLINE STARTER SNAPSHOT RESTORED"
                        }
                    } catch (error: Exception) {
                        mainHandler.post {
                            status.text = "SNAPSHOT RESTORE FAILED · " + error.javaClass.simpleName
                        }
                    }
                }
            }
            .show()
    }

    private fun refreshDatasetStats() {
        executor.execute {
            try {
                val stats = JSONObject(Python.getInstance().getModule("android_bridge")
                    .callAttr("scan_stats", filesDir.absolutePath).toString())
                mainHandler.post {
                    val bundledSource = prefs.getString("bundled_snapshot_id", null)
                    val total = stats.optInt("total")
                    val prefix = when {
                        !bundledSource.isNullOrBlank() -> "BUNDLED EMBER2024 STARTER · " + bundledSource
                        total == 0 -> "NO HISTORICAL SNAPSHOT INSTALLED"
                        else -> "LOCAL HISTORICAL INTELLIGENCE"
                    }
                    val coverage = stats.optJSONObject("by_file_type")?.keys()?.asSequence()
                        ?.joinToString(", ") { type -> type + ":" + stats.optJSONObject("by_file_type")?.optInt(type) }
                        ?.ifBlank { "none" } ?: "none"
                    datasetStatus.text = prefix + " · " + total +
                        " HASHES · " + stats.optInt("malicious") + " MALICIOUS · " +
                        stats.optInt("benign") + " BENIGN · TYPES " + coverage
                    if (starterSnapshotError != null) {
                        status.text = "STARTER SNAPSHOT INSTALL FAILED · " + starterSnapshotError
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
                val coverage = stats.optJSONObject("by_file_type")?.keys()?.asSequence()
                    ?.joinToString("\n") { type -> type + ": " + stats.optJSONObject("by_file_type")?.optInt(type) }
                    ?.ifBlank { "No file-type coverage" } ?: "No file-type coverage"
                val message = "Local historical indicators: " + total +
                    "\nMalicious labels: " + stats.optInt("malicious") +
                    "\nBenign labels: " + stats.optInt("benign") +
                    "\nDistinct imported sources: " + stats.optInt("source_count") +
                    "\n\nFile-type coverage:\n" + coverage +
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
        if (requestCode == REQUEST_EXPORT && resultCode != RESULT_OK) {
            pendingExportJson = null
            return
        }
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
            REQUEST_EXPORT -> {
                val destination = data.data ?: return
                val payload = pendingExportJson ?: return
                executor.execute {
                    try {
                        contentResolver.openOutputStream(destination, "w")?.use { output ->
                            output.write(payload.toByteArray(Charsets.UTF_8))
                        } ?: throw IllegalStateException("Android could not open the selected export destination")
                        pendingExportJson = null
                        mainHandler.post { status.text = "METADATA-ONLY EVIDENCE REPORT EXPORTED" }
                    } catch (error: Exception) {
                        mainHandler.post { status.text = "REPORT EXPORT FAILED · " + error.javaClass.simpleName }
                    }
                }
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
        val uniqueUris = uris.distinct()
        val acceptedUris = uniqueUris.take(MAX_SHARED_FILES)
        val notStarted = (uniqueUris.size - acceptedUris.size).coerceAtLeast(0)
        status.text = "SCANNING " + acceptedUris.size + " OF " + uniqueUris.size + " FILE(S) LOCALLY…"
        executor.execute {
            val output = mutableListOf<String>()
            var scannedCount = 0
            var failedCount = 0
            acceptedUris.forEach { uri ->
                try {
                    val name = displayName(uri)
                    val temp = copyUriToTemp(uri)
                    val json = try {
                        Python.getInstance().getModule("android_bridge")
                            .callAttr("scan_shared_file_path", temp.absolutePath, name, filesDir.absolutePath).toString()
                    } finally {
                        temp.delete()
                    }
                    val item = JSONObject(json)
                    val verdict = item.optString("verdict")
                    val snapshot = item.optJSONObject("snapshot") ?: JSONObject()
                    val intelMatch = item.optJSONObject("intelligence_match") ?: JSONObject()
                    val intelSource = intelMatch.optString("source").ifBlank { "No exact hash match" }
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
                        "Evidence report SHA-256: " + item.optString("report_sha256") + "\n" +
                        "Scanned at: " + item.optString("scanned_at") + "\n" +
                        "Historical snapshot: " + snapshot.optInt("total") + " hashes · " +
                        snapshot.optInt("malicious") + " malicious · " + snapshot.optInt("benign") + " benign\n" +
                        "Matched intelligence source: " + intelSource + "\n" +
                        "Evidence signals:\n" + item.optJSONArray("signals")?.toString(2).orEmpty() +
                        "\nAgent trace:\n" + item.optJSONArray("agent_trace")?.toString(2).orEmpty() + safetyNote
                    )
                    scannedCount += 1
                } catch (error: Exception) {
                    failedCount += 1
                    output.add("SCAN INCOMPLETE · " + error.javaClass.simpleName + ". The file was not modified.")
                }
            }

                .apply()
            mainHandler.post {
                results.text = output.joinToString("\n\n──────────────\n\n")
                status.text = "SCAN FINISHED · " + scannedCount + " SCANNED · " +
                    failedCount + " FAILED · " + notStarted + " NOT STARTED · LOCAL ONLY"
            }
        }
    }

    private fun sha256Hex(data: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(data).joinToString("") {
            "%02x".format(it.toInt() and 0xff)
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

    private fun copyUriToTemp(uri: Uri): java.io.File {
        val temp = java.io.File.createTempFile("satark-scan-", ".bin", cacheDir)
        try {
            contentResolver.openInputStream(uri)?.use { input ->
                temp.outputStream().use { output ->
                    val buffer = ByteArray(64 * 1024)
                    var total = 0L
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        total += count
                        if (total > maxBytes) throw IllegalArgumentException("File exceeds 64 MB scan limit")
                        output.write(buffer, 0, count)
                    }
                }
            } ?: throw IllegalStateException("Android could not open this shared file")
            return temp
        } catch (error: Exception) {
            temp.delete()
            throw error
        }
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
        val constraints = Constraints.Builder()
            .setRequiresBatteryNotLow(true)
            .setRequiresStorageNotLow(true)
            .build()
        val request = PeriodicWorkRequestBuilder<FolderScanWorker>(interval, unit)
            .setConstraints(constraints)
            .addTag(FOLDER_SCAN_TAG)
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
        WorkManager.getInstance(this).cancelUniqueWork(IMMEDIATE_FOLDER_SCAN_NAME)
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
        private const val MAX_SHARED_FILES = 20
    }
}
