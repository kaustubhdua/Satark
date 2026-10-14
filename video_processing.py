"""Video frame extraction and audio transcription helpers."""
import base64
import os
import shutil
import subprocess
import tempfile
from io import BytesIO

from PIL import Image

from satark_utils import safe_text
from config import MAX_UPLOAD_BYTES

# ------------------- Video: frame + audio extraction -------------------
# Videos are not sent to the vision model directly. Instead SATARK pulls a
# handful of representative frames (evenly spaced through the clip) with
# OpenCV and treats them exactly like an "Image" scan. If OpenCV or an
# audio-transcription path is unavailable in this environment, SATARK
# degrades gracefully and explains what could not be analyzed rather than
# crashing the whole scan.
MAX_VIDEO_FRAMES = 2  # kept minimal — every extra frame competes with the
# transcript and system prompt for the same tight tokens-per-minute budget
MAX_VIDEO_BYTES = MAX_UPLOAD_BYTES  # Keep video reads aligned with Streamlit server.maxUploadSize (50 MB).


def _video_dependencies_available():
    try:
        import cv2  # noqa: F401
        return True
    except Exception:
        return False


def extract_video_frames(uploaded_file, max_frames=MAX_VIDEO_FRAMES):
    """Extract up to `max_frames` evenly spaced frames from an uploaded video
    as PIL Images. Returns (frames, duration_seconds, warnings)."""
    import tempfile

    try:
        max_frames = int(max_frames)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("max_frames must be a positive integer.") from exc
    if max_frames < 1:
        raise ValueError("max_frames must be a positive integer.")

    try:
        import cv2
    except Exception as exc:
        raise RuntimeError(
            "Video frame extraction requires OpenCV (opencv-python-headless), "
            "which is not installed in this environment. Run "
            "`pip install opencv-python-headless --break-system-packages` and restart the app."
        ) from exc

    warnings = []
    try:
        uploaded_file.seek(0)
    except Exception:
        pass
    data = uploaded_file.read(MAX_VIDEO_BYTES + 1)
    if len(data) > MAX_VIDEO_BYTES:
        raise ValueError("This video is larger than the 50 MB upload limit SATARK can safely process in-session.")
    if not data:
        raise ValueError("The uploaded video appears to be empty or unreadable.")

    suffix = os.path.splitext(safe_text(getattr(uploaded_file, "name", "")))[1] or ".mp4"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name

    frames = []
    duration = 0.0
    try:
        capture = cv2.VideoCapture(tmp_path)
        if not capture.isOpened():
            raise ValueError("SATARK could not open this video file. It may be corrupted or in an unsupported codec.")

        fps = capture.get(cv2.CAP_PROP_FPS) or 0
        frame_count = int(capture.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
        duration = (frame_count / fps) if fps > 0 else 0.0

        if frame_count <= 0:
            # Fall back to sequential reads if metadata is unreliable.
            count = 0
            while True:
                ok, frame_bgr = capture.read()
                if not ok:
                    break
                count += 1
                # Metadata can be missing for short or variable-frame-rate clips.
                # Capture useful frames without requiring a 30-frame threshold.
                if len(frames) < max_frames:
                    stride = max(1, 30 // max_frames)
                    if count == 1 or count % stride == 0:
                        frames.append(_bgr_to_pil(frame_bgr))
                if len(frames) >= max_frames:
                    break
            if not frames:
                raise ValueError("SATARK could not read any frames from this video.")
        else:
            target_frames = min(max_frames, frame_count)
            indices = [int(i * (frame_count - 1) / max(1, target_frames - 1)) for i in range(target_frames)] if target_frames > 1 else [0]
            for idx in indices:
                capture.set(cv2.CAP_PROP_POS_FRAMES, idx)
                ok, frame_bgr = capture.read()
                if ok:
                    frames.append(_bgr_to_pil(frame_bgr))
            if not frames:
                raise ValueError("SATARK could not extract readable frames from this video.")

    finally:
        try:
            if "capture" in locals():
                capture.release()
        except Exception:
            pass
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

    return frames, duration, warnings


def _bgr_to_pil(frame_bgr):
    import cv2
    frame_rgb = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2RGB)
    return Image.fromarray(frame_rgb)


def pil_frames_to_data_urls(frames, max_side=512):
    """Convert extracted PIL frames into compact JPEG data URLs for the vision
    model. Kept small (512px, low JPEG quality) because local model context windows
    has a tight tokens-per-minute budget shared across every frame AND the
    audio transcript AND the system prompt in the same request."""
    from io import BytesIO
    urls = []
    for image in frames:
        image = image.convert("RGB")
        if max(image.size) > max_side:
            scale = max_side / max(image.size)
            image = image.resize((max(1, int(image.width * scale)), max(1, int(image.height * scale))))
        for quality in (55, 42, 30):
            buffer = BytesIO()
            image.save(buffer, format="JPEG", quality=quality, optimize=True)
            encoded = base64.b64encode(buffer.getvalue()).decode("utf-8")
            if len(encoded) <= 400_000 or quality == 30:
                urls.append(f"data:image/jpeg;base64,{encoded}")
                break
    return urls


def transcribe_video_audio(uploaded_file, client=None):
    """Transcribe a short video audio track with a locally installed Whisper model.

    No hosted transcription API is called. Install faster-whisper from
    requirements-local-ai.txt and allow the model weights to be downloaded
    once, or pre-cache the model for offline operation.
    """
    del client  # Kept for compatibility with the existing caller.
    if shutil.which("ffmpeg") is None:
        return ""

    try:
        uploaded_file.seek(0)
        data = uploaded_file.read(MAX_VIDEO_BYTES + 1)
        if len(data) > MAX_VIDEO_BYTES:
            return ""
    except Exception:
        return ""

    suffix = os.path.splitext(safe_text(getattr(uploaded_file, "name", "")))[1] or ".mp4"
    video_path = None
    audio_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as video_file:
            video_file.write(data)
            video_path = video_file.name
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as audio_file:
            audio_path = audio_file.name

        completed = subprocess.run(
            [
                "ffmpeg", "-nostdin", "-y", "-v", "error",
                "-i", video_path, "-vn", "-t", "180",
                "-ac", "1", "-ar", "16000", "-c:a", "pcm_s16le", audio_path,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=120,
            check=False,
        )
        if completed.returncode != 0 or not os.path.exists(audio_path):
            return ""
        audio_size = os.path.getsize(audio_path)
        if audio_size == 0 or audio_size > 32 * 1024 * 1024:
            return ""

        try:
            from faster_whisper import WhisperModel
        except ImportError:
            return ""

        model_size = os.getenv("SATARK_WHISPER_MODEL", "base").strip() or "base"
        device = os.getenv("SATARK_WHISPER_DEVICE", "cpu").strip() or "cpu"
        compute_type = os.getenv("SATARK_WHISPER_COMPUTE_TYPE", "int8").strip() or "int8"
        model = WhisperModel(model_size, device=device, compute_type=compute_type)
        segments, _info = model.transcribe(audio_path, beam_size=1, vad_filter=True)
        parts = []
        total = 0
        for segment in segments:
            text = safe_text(getattr(segment, "text", "")).strip()
            if not text:
                continue
            remaining = 3000 - total
            if remaining <= 0:
                break
            text = text[:remaining]
            parts.append(text)
            total += len(text)
        return " ".join(parts).strip()
    except Exception:
        return ""
    finally:
        for path in (video_path, audio_path):
            if path:
                try:
                    os.unlink(path)
                except OSError:
                    pass
