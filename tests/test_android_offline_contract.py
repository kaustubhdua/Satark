"""Guard the Android app's privacy and offline-first product contract."""
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
ANDROID = ROOT / "android"
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
FORBIDDEN_MODULES = {"requests", "httpx", "urllib", "socket", "aiohttp", "supabase"}


class AndroidOfflineContractTests(unittest.TestCase):
    def test_manifest_does_not_request_network_permissions(self):
        manifest = ET.parse(ANDROID / "app/src/main/AndroidManifest.xml").getroot()
        permissions = {
            node.attrib.get(ANDROID_NS + "name")
            for node in manifest.findall("uses-permission")
        }
        self.assertNotIn("android.permission.INTERNET", permissions)
        self.assertNotIn("android.permission.ACCESS_NETWORK_STATE", permissions)
        application = manifest.find("./application")
        self.assertEqual(application.attrib.get(ANDROID_NS + "allowBackup"), "false")

    def test_manifest_exposes_share_receivers(self):
        manifest = ET.parse(ANDROID / "app/src/main/AndroidManifest.xml").getroot()
        activity = manifest.find("./application/activity")
        self.assertIsNotNone(activity)
        actions = {
            node.attrib.get(ANDROID_NS + "name")
            for node in activity.findall("./intent-filter/action")
        }
        self.assertIn("android.intent.action.SEND", actions)
        self.assertIn("android.intent.action.SEND_MULTIPLE", actions)

    def test_app_has_branded_launcher_mark_and_dark_theme(self):
        manifest = ET.parse(ANDROID / "app/src/main/AndroidManifest.xml").getroot()
        application = manifest.find("./application")
        self.assertEqual(application.attrib.get(ANDROID_NS + "icon"), "@drawable/ic_satark_mark")
        self.assertEqual(application.attrib.get(ANDROID_NS + "theme"), "@style/AppTheme")
        ET.parse(ANDROID / "app/src/main/res/drawable/ic_satark_mark.xml")
        styles = ET.parse(ANDROID / "app/src/main/res/values/styles.xml").getroot()
        theme = styles.find("./style[@name='AppTheme']")
        self.assertIsNotNone(theme)
        values = {item.attrib.get("name"): item.text for item in theme.findall("item")}
        self.assertEqual(values.get("android:colorAccent"), "#78E0C1")
        self.assertEqual(values.get("android:statusBarColor"), "#08101B")

    def test_android_16_target_and_edge_to_edge_insets(self):
        gradle = (ANDROID / "app/build.gradle.kts").read_text(encoding="utf-8")
        self.assertIn("targetSdk = 36", gradle)
        self.assertIn('androidx.core:core-ktx:1.16.0', gradle)
        source = (ANDROID / "app/src/main/java/com/satark/mobile/MainActivity.kt").read_text(encoding="utf-8")
        self.assertIn("WindowCompat.setDecorFitsSystemWindows(window, false)", source)
        self.assertIn("WindowInsetsCompat.Type.systemBars()", source)
        self.assertIn("ViewCompat.requestApplyInsets(scroll)", source)

    def test_android_python_has_no_network_client_imports(self):
        sources = list((ANDROID / "app/src/main/python").rglob("*.py"))
        self.assertTrue(sources, "Android Python scanner sources must exist")
        for path in sources:
            for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                stripped = line.strip()
                module = None
                if stripped.startswith("import "):
                    module = stripped[7:].split(",")[0].strip().split(".")[0].split(" ")[0]
                elif stripped.startswith("from "):
                    module = stripped[5:].split(" ")[0].split(".")[0]
                if module:
                    self.assertNotIn(
                        module,
                        FORBIDDEN_MODULES,
                        f"{path.relative_to(ROOT)}:{line_number} imports {module}",
                    )

    def test_android_scanner_is_the_same_python_engine_as_root(self):
        pairs = (
            ("file_guard/engine.py", "android/app/src/main/python/file_guard/engine.py"),
            ("file_guard/agents.py", "android/app/src/main/python/file_guard/agents.py"),
            ("file_guard/intelligence.py", "android/app/src/main/python/file_guard/intelligence.py"),
            ("file_guard/history.py", "android/app/src/main/python/file_guard/history.py"),
            ("file_guard/report.py", "android/app/src/main/python/file_guard/report.py"),
            ("file_guard/structure.py", "android/app/src/main/python/file_guard/structure.py"),
        )
        for root_path, android_path in pairs:
            with self.subTest(module=root_path):
                self.assertEqual(
                    (ROOT / root_path).read_bytes(),
                    (ROOT / android_path).read_bytes(),
                    f"Android-bundled {android_path} drifted from {root_path}",
                )

    def test_folder_scan_work_is_unique_and_deduplicated(self):
        source = (ANDROID / "app/src/main/java/com/satark/mobile/MainActivity.kt").read_text(encoding="utf-8")
        self.assertIn('enqueueUniqueWork(\n            IMMEDIATE_FOLDER_SCAN_NAME', source)
        self.assertIn("androidx.work.ExistingWorkPolicy.REPLACE", source)
        self.assertIn("IMMEDIATE_FOLDER_SCAN_NAME", source)

    def test_worker_has_explicit_scan_limits_and_cancellation_checks(self):
        source = (ANDROID / "app/src/main/java/com/satark/mobile/FolderScanWorker.kt").read_text(encoding="utf-8")
        self.assertIn("private const val MAX_FILES = 1000", source)
        self.assertIn("private const val MAX_DEPTH = 8", source)
        self.assertIn("private const val MAX_DIRECTORIES = 2000", source)
        self.assertIn("private const val MAX_FILE_BYTES = 64L * 1024L * 1024L", source)
        self.assertIn("private const val MAX_TOTAL_BYTES = 512L * 1024L * 1024L", source)
        self.assertIn("!isStopped", source)

    def test_metadata_only_evidence_report_export_uses_system_document_picker(self):
        source = (ANDROID / "app/src/main/java/com/satark/mobile/MainActivity.kt").read_text(encoding="utf-8")
        self.assertIn('ACTION_CREATE_DOCUMENT', source)
        self.assertIn('type = "application/json"', source)
        self.assertIn('REQUEST_EXPORT', source)
        self.assertIn("exportLatestEvidenceReport", source)
        self.assertIn("pendingExportJson = null", source)

    def test_audit_status_discloses_legacy_unlinked_history(self):
        source = (ANDROID / "app/src/main/java/com/satark/mobile/MainActivity.kt").read_text(encoding="utf-8")
        history = (ANDROID / "app/src/main/python/file_guard/history.py").read_text(encoding="utf-8")
        self.assertIn('payload.optBoolean("complete", true)', source)
        self.assertIn('unlinked_history_records', history)
        self.assertIn("LEGACY RECORD(S) UNLINKED", source)

    def test_android_history_exposes_local_hash_chain_verification(self):
        bridge = (ANDROID / "app/src/main/python/android_bridge.py").read_text(encoding="utf-8")
        activity = (ANDROID / "app/src/main/java/com/satark/mobile/MainActivity.kt").read_text(encoding="utf-8")
        self.assertIn("def verify_scan_audit", bridge)
        self.assertIn('callAttr("verify_scan_audit"', activity)
        self.assertIn('Verify local evidence chain', activity)
        self.assertIn('audit?.optString("entry_sha256")', activity)
        self.assertIn("not a digital signature or remote proof of authenticity", activity)

    def test_folder_scan_persists_and_surfaces_partial_scan_status(self):
        worker = (ANDROID / "app/src/main/java/com/satark/mobile/FolderScanWorker.kt").read_text(encoding="utf-8")
        activity = (ANDROID / "app/src/main/java/com/satark/mobile/MainActivity.kt").read_text(encoding="utf-8")
        self.assertIn('putInt("last_folder_scan_examined", examinedFiles)', worker)
        self.assertIn('putInt("last_folder_scan_skipped", skipped)', worker)
        self.assertIn('putBoolean("last_folder_scan_limit_reached", hitLimit)', worker)
        self.assertIn("LIMIT REACHED — RUN AGAIN TO CONTINUE", activity)
        self.assertIn("SCANNED · ", activity)
        self.assertIn("SKIPPED · ", activity)

    def test_abandoned_scan_temp_files_are_cleaned_on_app_and_worker_start(self):
        source = (ANDROID / "app/src/main/java/com/satark/mobile/ScanTempFiles.kt").read_text(encoding="utf-8")
        activity = (ANDROID / "app/src/main/java/com/satark/mobile/MainActivity.kt").read_text(encoding="utf-8")
        worker = (ANDROID / "app/src/main/java/com/satark/mobile/FolderScanWorker.kt").read_text(encoding="utf-8")
        self.assertIn('listOf("satark-scan-", "satark-folder-")', source)
        self.assertIn("TimeUnit.HOURS.toMillis(6)", source)
        self.assertIn("ScanTempFiles.cleanup(cacheDir)", activity)
        self.assertIn("ScanTempFiles.cleanup(applicationContext.cacheDir)", worker)

    def test_folder_worker_bounds_attempted_files_and_directories(self):
        worker = (ANDROID / "app/src/main/java/com/satark/mobile/FolderScanWorker.kt").read_text(encoding="utf-8")
        self.assertIn("private const val MAX_FILES = 1000", worker)
        self.assertIn("private const val MAX_DIRECTORIES = 2000", worker)
        self.assertIn("examinedFiles < MAX_FILES", worker)
        self.assertIn('"examined_files" to examinedFiles', worker)
        self.assertIn('"limit_reached" to hitLimit', worker)

    def test_stop_background_scans_cancels_immediate_and_periodic_work(self):
        source = (ANDROID / "app/src/main/java/com/satark/mobile/MainActivity.kt").read_text(encoding="utf-8")
        stop = source[source.index("private fun stopBackgroundScans"):source.index("private fun enqueueFolderScan")]
        self.assertIn("cancelUniqueWork(IMMEDIATE_FOLDER_SCAN_NAME)", stop)
        self.assertIn("cancelAllWorkByTag(FOLDER_SCAN_TAG)", stop)
        self.assertIn(".addTag(FOLDER_SCAN_TAG)", source)

    def test_share_scan_reports_files_beyond_the_per_share_limit(self):
        source = (ANDROID / "app/src/main/java/com/satark/mobile/MainActivity.kt").read_text(encoding="utf-8")
        self.assertIn("private const val MAX_SHARED_FILES = 20", source)
        self.assertIn("val notStarted = (uniqueUris.size - acceptedUris.size)", source)
        self.assertIn('" NOT STARTED · LOCAL ONLY"', source)
        self.assertIn('"last_scan_not_started"', source)

    def test_ember_import_requires_pinned_dataset_and_source_archive_provenance(self):
        source = (ANDROID / "app/src/main/java/com/satark/mobile/MainActivity.kt").read_text(encoding="utf-8")
        self.assertIn('manifest.optString("upstream_revision") != pinnedRevision', source)
        self.assertIn('manifest.optString("collection_window") != "2023-09-24 through 2024-12-14"', source)
        self.assertIn('manifest.optJSONObject("source_manifest")', source)
        self.assertIn('sourceManifest.optString("dataset_revision") != pinnedRevision', source)
        self.assertIn('sourceManifest.optString("sha256").matches', source)
        self.assertIn("sourceManifests.size != 1", source)
        self.assertIn("sha256Hex(sourceManifestBytes)", source)
        self.assertIn('sourceDocument.optString("dataset_revision") != pinnedRevision', source)
        self.assertIn('archive.optString("sha256").matches', source)
        self.assertIn('exported_rows', source)

    def test_dataset_import_has_a_historical_snapshot_id_default(self):
        source = (ANDROID / "app/src/main/java/com/satark/mobile/MainActivity.kt").read_text(encoding="utf-8")
        self.assertIn('setText("EMBER2024-2024-12-14")', source)
        self.assertIn("EMBER2024 IMPORT REQUIRES EXACTLY ONE CONVERTER MANIFEST", source)

    def test_share_intake_limit_is_explicit_and_never_silently_drops_files(self):
        source = (ANDROID / "app/src/main/java/com/satark/mobile/MainActivity.kt").read_text(encoding="utf-8")
        self.assertIn("private const val MAX_SHARED_FILES = 20", source)
        self.assertIn("val uniqueUris = uris.distinct()", source)
        self.assertIn("val acceptedUris = uniqueUris.take(MAX_SHARED_FILES)", source)
        self.assertIn("NOT SCANNED", source)
        self.assertIn("last_scan_not_started", source)

    def test_android_scan_path_streams_from_bounded_temporary_files(self):
        activity = (ANDROID / "app/src/main/java/com/satark/mobile/MainActivity.kt").read_text(encoding="utf-8")
        worker = (ANDROID / "app/src/main/java/com/satark/mobile/FolderScanWorker.kt").read_text(encoding="utf-8")
        bridge = (ANDROID / "app/src/main/python/android_bridge.py").read_text(encoding="utf-8")
        engine = (ANDROID / "app/src/main/python/file_guard/engine.py").read_text(encoding="utf-8")

        self.assertIn("copyUriToTemp(uri)", activity)
        self.assertIn("scan_shared_file_path", activity)
        self.assertIn("temp.delete()", activity)
        self.assertIn("copyUriToTemp(documentUri)", worker)
        self.assertIn("scan_shared_file_path", worker)
        self.assertIn("tempFile.delete()", worker)
        self.assertIn("def scan_shared_file_path", bridge)
        self.assertIn("def scan_path(", engine)
        self.assertIn("digest.update(chunk)", engine)
        self.assertIn("header.extend(chunk[:4096 - len(header)])", engine)

    def test_ember_import_requires_checksum_verified_manifest(self):
        activity = (ANDROID / "app/src/main/java/com/satark/mobile/MainActivity.kt").read_text(encoding="utf-8")
        bridge = (ANDROID / "app/src/main/python/android_bridge.py").read_text(encoding="utf-8")
        self.assertIn("EMBER2024 IMPORT REQUIRES EXACTLY ONE CONVERTER MANIFEST", activity)
        self.assertIn("expected_sha256", bridge)
        self.assertIn("actual != expected", bridge)
        self.assertIn("checksum_verified", bridge)

    def test_periodic_scans_defer_when_battery_or_storage_is_low(self):
        source = (ANDROID / "app/src/main/java/com/satark/mobile/MainActivity.kt").read_text(encoding="utf-8")
        self.assertIn(".setRequiresBatteryNotLow(true)", source)
        self.assertIn(".setRequiresStorageNotLow(true)", source)


if __name__ == "__main__":
    unittest.main()
