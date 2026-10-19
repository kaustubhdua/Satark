"""Regression tests for bounded upload preprocessing."""

import unittest
from io import BytesIO
from types import SimpleNamespace
from unittest.mock import patch

from PIL import Image

from input_processing import (
    MAX_IMAGE_BYTES,
    MAX_IMAGE_PIXELS,
    MAX_PDF_BYTES,
    extract_pdf_text,
    image_to_data_url,
)


class InputProcessingTests(unittest.TestCase):
    def test_invalid_image_has_user_facing_error(self):
        upload = BytesIO(b"not an image")
        upload.name = "bad.png"
        with self.assertRaisesRegex(ValueError, "could not read this image"):
            image_to_data_url(upload)

    def test_oversized_image_is_rejected_before_decode(self):
        upload = SimpleNamespace(size=MAX_IMAGE_BYTES + 1, name="large.png")
        with self.assertRaisesRegex(ValueError, "10 MB processing limit"):
            image_to_data_url(upload)

    def test_image_pixel_limit_is_rejected(self):
        upload = BytesIO(b"image")
        upload.name = "pixel-heavy.png"
        fake_image = SimpleNamespace(size=(MAX_IMAGE_PIXELS + 1, 1), convert=lambda *_: fake_image, load=lambda: None)
        with patch("input_processing.Image.open", return_value=fake_image):
            with self.assertRaisesRegex(ValueError, "too many pixels"):
                image_to_data_url(upload)

    def test_pdf_page_tree_failure_has_user_facing_error(self):
        class BrokenReader:
            @property
            def pages(self):
                raise RuntimeError("broken cross-reference table")

        upload = BytesIO(b"%PDF-1.7")
        with patch("input_processing.PdfReader", return_value=BrokenReader()):
            with self.assertRaisesRegex(ValueError, "could not read this PDF"):
                extract_pdf_text(upload)

    def test_oversized_pdf_is_rejected_before_parse(self):
        upload = SimpleNamespace(size=MAX_PDF_BYTES + 1, name="large.pdf")
        with self.assertRaisesRegex(ValueError, "25 MB processing limit"):
            extract_pdf_text(upload)

    def test_valid_image_is_encoded(self):
        buffer = BytesIO()
        Image.new("RGB", (16, 12), "white").save(buffer, format="PNG")
        buffer.seek(0)
        buffer.name = "sample.png"
        value = image_to_data_url(buffer)
        self.assertTrue(value.startswith("data:image/jpeg;base64,"))


    def test_decompression_bomb_is_rejected_with_bounded_error(self):
        upload = BytesIO(b"image")
        upload.name = "bomb.png"
        with patch("input_processing.Image.open", side_effect=Image.DecompressionBombError("too many pixels")):
            with self.assertRaisesRegex(ValueError, "too large to process safely"):
                image_to_data_url(upload)

    def test_corrupt_pdf_is_normalized_to_user_safe_error(self):
        upload = BytesIO(b"not a pdf")
        upload.name = "broken.pdf"
        with patch("input_processing.PdfReader", side_effect=RuntimeError("internal parser detail")):
            with self.assertRaisesRegex(ValueError, "could not read this PDF") as caught:
                extract_pdf_text(upload)
        self.assertNotIn("internal parser detail", str(caught.exception))

    def test_pdf_with_no_extractable_text_fails_closed(self):
        class EmptyPage:
            def extract_text(self):
                return ""

        class EmptyReader:
            pages = [EmptyPage()]

        upload = BytesIO(b"%PDF-1.7")
        with patch("input_processing.PdfReader", return_value=EmptyReader()):
            with self.assertRaisesRegex(ValueError, "No readable text"):
                extract_pdf_text(upload)

    def test_upload_size_falls_back_to_file_like_length(self):
        from input_processing import _uploaded_size
        upload = BytesIO(b"12345")
        self.assertEqual(_uploaded_size(upload), 5)



    def test_pdf_with_readable_text_is_extracted(self):
        class TextPage:
            def extract_text(self):
                return "Synthetic incident note with a readable timestamp."

        class TextReader:
            pages = [TextPage()]

        upload = BytesIO(b"%PDF-1.7 synthetic fixture")
        with patch("input_processing.PdfReader", return_value=TextReader()):
            self.assertEqual(
                extract_pdf_text(upload),
                "Synthetic incident note with a readable timestamp.",
            )

    def test_encrypted_pdf_returns_bounded_user_safe_error(self):
        upload = BytesIO(b"%PDF-1.7 encrypted fixture")
        with patch("input_processing.PdfReader", side_effect=RuntimeError("private parser detail")):
            with self.assertRaisesRegex(ValueError, "corrupted, encrypted, or unsupported") as caught:
                extract_pdf_text(upload)
        self.assertNotIn("private parser detail", str(caught.exception))

if __name__ == "__main__":
    unittest.main()
