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
        permissions = {node.attrib.get(ANDROID_NS + "name") for node in manifest.findall("uses-permission")}
        self.assertNotIn("android.permission.INTERNET", permissions)
        self.assertNotIn("android.permission.ACCESS_NETWORK_STATE", permissions)
        application = manifest.find("./application")
        self.assertEqual(application.attrib.get(ANDROID_NS + "allowBackup"), "false")

    def test_manifest_exposes_share_receivers(self):
        manifest = ET.parse(ANDROID / "app/src/main/AndroidManifest.xml").getroot()
        activity = manifest.find("./application/activity")
        self.assertIsNotNone(activity)
        actions = {node.attrib.get(ANDROID_NS + "name") for node in activity.findall("./intent-filter/action")}
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
                    self.assertNotIn(module, FORBIDDEN_MODULES,
                                     f"{path.relative_to(ROOT)}:{line_number} imports {module}")

    def test_android_scanner_is_the_same_python_engine_as_root(self):
        pairs = (
            ("file_guard/engine.py", "android/app/src/main/python/file_guard/engine.py"),
            ("file_guard/agents.py", "android/app/src/main/python/file_guard/agents.py"),
            ("file_guard/intelligence.py", "android/app/src/main/python/file_guard/intelligence.py"),
            ("file_guard/history.py", "android/app/src/main/python/file_guard/history.py"),
            ("file_guard/report.py", "android/app/src/main/python/file_guard/report.py"),

        )
        for root_path, android_path in pairs:
            with self.subTest(module=root_path):
                self.assertEqual((ROOT / root_path).read_bytes(), (ROOT / android_path).read_bytes(),
                                 f"Android-bundled {android_path} drifted from {root_path}")

    def test_folder_scan_work_is_unique_and_deduplicated(self):
        source = (ANDROID / "app/src/main/java/com/satark/mobile/MainActivity.kt").read_text(encoding="utf-8")
        self.assertIn('enqueueUniqueWork(\n            IMMEDIATE_FOLDER_SCAN_NAME', source)
        self.assertIn("androidx.work.ExistingWorkPolicy.REPLACE", source)
        self.assertIn("IMMEDIATE_FOLDER_SCAN_NAME", source)

    def test_android_snapshot_installation_runs_off_the_ui_thread(self):
        source = (ANDROID / "app/src/main/java/com/satark/mobile/MainActivity.kt").read_text(encoding="utf-8")
        on_create = source.split("override fun onCreate", 1)[1].split("override fun onNewIntent", 1)[0]
        self.assertLess(on_create.index("executor.execute"), on_create.index("installBundledSnapshotIfMissing()"))
        self.assertIn("ensurePython()", on_create)
        self.assertIn("mainHandler.post", on_create)

    def test_android_installs_only_checksum_verified_bundled_historical_database(self):
        source = (ANDROID / "app/src/main/java/com/satark/mobile/MainActivity.kt").read_text(encoding="utf-8")
        workflow = (ROOT / ".github/workflows/android-file-guard.yml").read_text(encoding="utf-8")
        self.assertIn("installBundledSnapshotIfMissing()", source)
        self.assertIn('assets.open("ember2024-starter.sqlite3")', source)
        self.assertIn('assets.open("ember2024-starter.json")', source)
        self.assertIn('metadata.optString("dataset_revision") != pinnedRevision', source)
        self.assertIn("actualSha256 != expectedSha256", source)
        self.assertIn('File(filesDir, "file_guard_intelligence.sqlite3")', source)
        self.assertIn("Restore bundled EMBER2024 APK starter snapshot", source)
        self.assertIn("Build pinned EMBER2024 APK starter database", workflow)
        self.assertIn("Package verified historical starter database into offline app", workflow)

    def test_worker_has_explicit_scan_limits_and_cancellation_checks(self):
        source = (ANDROID / "app/src/main/java/com/satark/mobile/FolderScanWorker.kt").read_text(encoding="utf-8")
        self.assertIn("private const val MAX_FILES = 1000", source)
        self.assertIn("private const val MAX_DEPTH = 8", source)
        self.assertIn("private const val MAX_DIRECTORIES = 2000", source)
        self.assertIn("private const val MAX_FILE_BYTES = 64L * 1024L * 1024L", source)
        self.assertIn("private const val MAX_TOTAL_BYTES = 512L * 1024L * 1024L", source)
        self.assertIn("!isStopped", source)




if __name__ == "__main__":
    unittest.main()
