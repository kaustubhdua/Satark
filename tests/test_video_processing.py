"""Tests for the extracted video processing helpers."""

import unittest
import subprocess
from types import SimpleNamespace
from io import BytesIO
from unittest.mock import patch, Mock

from PIL import Image
import numpy as np

from config import MAX_UPLOAD_BYTES
from video_processing import (
    MAX_VIDEO_BYTES,
    MAX_VIDEO_FRAMES,
    extract_video_frames,
    pil_frames_to_data_urls,
    transcribe_video_audio,
)


class VideoProcessingTests(unittest.TestCase):
    def test_video_limits_are_positive(self):
        self.assertGreater(MAX_VIDEO_FRAMES, 0)
        self.assertGreater(MAX_VIDEO_BYTES, 0)
        self.assertEqual(MAX_VIDEO_BYTES, MAX_UPLOAD_BYTES)
        self.assertLessEqual(MAX_VIDEO_BYTES, 50 * 1024 * 1024)

    def test_invalid_max_frames_is_rejected_before_opencv_loading(self):
        upload = BytesIO(b"not a video")
        upload.name = "sample.mp4"
        with patch.dict("sys.modules", {"cv2": None}):
            with self.assertRaises(ValueError):
                extract_video_frames(upload, max_frames=0)

    def test_frames_are_encoded_as_jpeg_data_urls(self):
        image = Image.new("RGB", (32, 24), "white")
        urls = pil_frames_to_data_urls([image])
        self.assertEqual(len(urls), 1)
        self.assertTrue(urls[0].startswith("data:image/jpeg;base64,"))

    def test_empty_frames_return_empty_list(self):
        self.assertEqual(pil_frames_to_data_urls([]), [])

    def test_audio_transcription_gracefully_handles_missing_client(self):
        upload = BytesIO(b"not a video")
        upload.name = "sample.mp4"
        self.assertEqual(transcribe_video_audio(upload, None), "")

    def test_audio_transcription_gracefully_handles_missing_ffmpeg(self):
        upload = BytesIO(b"not a video")
        upload.name = "sample.mp4"
        with patch("video_processing.shutil.which", return_value=None):
            self.assertEqual(transcribe_video_audio(upload, Mock()), "")

    def test_audio_transcription_gracefully_handles_ffmpeg_failure(self):
        upload = BytesIO(b"not a video")
        upload.name = "sample.mp4"
        failed = Mock(returncode=1)
        with patch("video_processing.shutil.which", return_value="/usr/bin/ffmpeg"), \
             patch("video_processing.subprocess.run", return_value=failed):
            self.assertEqual(transcribe_video_audio(upload, Mock()), "")



    def test_missing_opencv_returns_actionable_error(self):
        upload = BytesIO(b"synthetic video bytes")
        upload.name = "sample.mp4"
        with patch.dict("sys.modules", {"cv2": None}):
            with self.assertRaisesRegex(RuntimeError, "requires OpenCV"):
                extract_video_frames(upload)

    def test_malformed_video_is_rejected_and_capture_is_released(self):
        capture = Mock()
        capture.isOpened.return_value = False
        fake_cv2 = SimpleNamespace(
            VideoCapture=Mock(return_value=capture),
            CAP_PROP_FPS=1,
            CAP_PROP_FRAME_COUNT=2,
            CAP_PROP_POS_FRAMES=3,
            COLOR_BGR2RGB=4,
        )
        upload = BytesIO(b"not a video")
        upload.name = "sample.mp4"
        with patch.dict("sys.modules", {"cv2": fake_cv2}):
            with self.assertRaisesRegex(ValueError, "could not open this video"):
                extract_video_frames(upload)
        capture.release.assert_called_once()

    def test_valid_video_extracts_bounded_representative_frames(self):
        capture = Mock()
        capture.isOpened.return_value = True
        capture.get.side_effect = lambda prop: {
            1: 2.0,  # FPS
            2: 3,    # frame count
        }[prop]
        capture.read.return_value = (True, np.zeros((12, 16, 3), dtype=np.uint8))
        fake_cv2 = SimpleNamespace(
            VideoCapture=Mock(return_value=capture),
            CAP_PROP_FPS=1,
            CAP_PROP_FRAME_COUNT=2,
            CAP_PROP_POS_FRAMES=3,
            COLOR_BGR2RGB=4,
            cvtColor=lambda frame, _code: frame,
        )
        upload = BytesIO(b"synthetic video bytes")
        upload.name = "sample.mp4"
        with patch.dict("sys.modules", {"cv2": fake_cv2}):
            frames, duration, warnings = extract_video_frames(upload, max_frames=2)
        self.assertEqual(len(frames), 2)
        self.assertAlmostEqual(duration, 1.5)
        self.assertEqual(warnings, [])
        self.assertEqual(capture.set.call_count, 2)
        self.assertEqual(frames[0].size, (16, 12))
        capture.release.assert_called_once()

    def test_unreadable_video_frames_fail_safely(self):
        capture = Mock()
        capture.isOpened.return_value = True
        capture.get.side_effect = lambda prop: {1: 0.0, 2: 0}[prop]
        capture.read.return_value = (False, None)
        fake_cv2 = SimpleNamespace(
            VideoCapture=Mock(return_value=capture),
            CAP_PROP_FPS=1,
            CAP_PROP_FRAME_COUNT=2,
            CAP_PROP_POS_FRAMES=3,
            COLOR_BGR2RGB=4,
        )
        upload = BytesIO(b"synthetic video bytes")
        upload.name = "sample.mp4"
        with patch.dict("sys.modules", {"cv2": fake_cv2}):
            with self.assertRaisesRegex(ValueError, "could not read any frames"):
                extract_video_frames(upload)
        capture.release.assert_called_once()

    def test_audio_extraction_timeout_returns_empty_transcript(self):
        upload = BytesIO(b"synthetic video bytes")
        upload.name = "sample.mp4"
        with patch("video_processing.shutil.which", return_value="/usr/bin/ffmpeg"), patch(
            "video_processing.subprocess.run",
            side_effect=subprocess.TimeoutExpired("ffmpeg", 120),
        ):
            self.assertEqual(transcribe_video_audio(upload), "")

    def test_missing_whisper_model_weights_return_empty_transcript(self):
        upload = BytesIO(b"synthetic video bytes")
        upload.name = "sample.mp4"
        whisper = SimpleNamespace(WhisperModel=Mock(side_effect=OSError("model weights unavailable")))
        completed = Mock(returncode=0)
        with patch("video_processing.shutil.which", return_value="/usr/bin/ffmpeg"), patch(
            "video_processing.subprocess.run", return_value=completed
        ), patch("video_processing.os.path.exists", return_value=True), patch(
            "video_processing.os.path.getsize", return_value=1
        ), patch.dict("sys.modules", {"faster_whisper": whisper}):
            self.assertEqual(transcribe_video_audio(upload), "")

    def test_missing_whisper_package_returns_empty_transcript(self):
        upload = BytesIO(b"synthetic video bytes")
        upload.name = "sample.mp4"
        with patch("video_processing.shutil.which", return_value="/usr/bin/ffmpeg"), patch(
            "video_processing.subprocess.run", return_value=Mock(returncode=0)
        ), patch("video_processing.os.path.exists", return_value=True), patch(
            "video_processing.os.path.getsize", return_value=1
        ), patch.dict("sys.modules", {"faster_whisper": None}):
            self.assertEqual(transcribe_video_audio(upload), "")

if __name__ == "__main__":
    unittest.main()
