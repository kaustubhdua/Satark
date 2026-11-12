"""Unit tests for Android emulator foreground-activity recognition."""
import unittest

from scripts.android_emulator_smoke import is_satark_foreground


class ForegroundActivityTests(unittest.TestCase):
    def test_accepts_android_activity_record_format(self):
        snapshot = "topResumedActivity=ActivityRecord{ab12 u0 com.satark.mobile/.MainActivity t42}"
        self.assertTrue(is_satark_foreground(snapshot))

    def test_accepts_fully_qualified_window_focus_format(self):
        snapshot = "mCurrentFocus=Window{ab12 u0 com.satark.mobile/com.satark.mobile.MainActivity}"
        self.assertTrue(is_satark_foreground(snapshot))

    def test_accepts_activity_dump_with_component_on_separate_lines(self):
        snapshot = (
            "ACTIVITY com.satark.mobile/.MainActivity 1a2b3c pid=1234\n"
            "  state=RESUMED"
        )
        self.assertTrue(is_satark_foreground(snapshot))

    def test_rejects_permission_dialog_even_if_app_process_is_present(self):
        snapshot = (
            "topResumedActivity=ActivityRecord{ab12 u0 "
            "com.android.permissioncontroller/.GrantPermissionsActivity t42}\n"
            "mResumedActivity=ActivityRecord{cd34 u0 com.satark.mobile/.MainActivity t41}\n"
            "mFocusedApp=ActivityRecord{ef56 u0 com.satark.mobile/.MainActivity t40}"
        )
        self.assertFalse(is_satark_foreground(snapshot))

    def test_rejects_unrelated_foreground_application(self):
        self.assertFalse(is_satark_foreground(
            "mCurrentFocus=Window{ab12 u0 com.android.settings/.Settings}"
        ))

    def test_rejects_empty_snapshot(self):
        self.assertFalse(is_satark_foreground(""))


if __name__ == "__main__":
    unittest.main()
