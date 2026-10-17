import pymupdf
import pytest

from invisible_text_watermark import InvisibleTextWatermark
from watermarking_method import InvalidKeyError, SecretNotFoundError


@pytest.fixture
def valid_pdf():
    document = pymupdf.open()
    document.new_page()
    pdf_bytes = document.tobytes()
    document.close()
    return pdf_bytes


def test_invisible_text_watermark_round_trip(valid_pdf):
    wm = InvisibleTextWatermark()

    secret = "Phase I invisible text watermark test"
    key = "test-key-123"

    assert wm.is_watermark_applicable(valid_pdf)

    watermarked = wm.add_watermark(
        valid_pdf,
        secret,
        key,
    )

    assert wm.read_secret(watermarked, key) == secret


def test_invisible_text_watermark_wrong_key(valid_pdf):
    wm = InvisibleTextWatermark()

    secret = "Phase I invisible text watermark test"
    correct_key = "test-key-123"
    wrong_key = "wrong-key-456"

    watermarked = wm.add_watermark(
        valid_pdf,
        secret,
        correct_key,
    )

    with pytest.raises(InvalidKeyError):
        wm.read_secret(watermarked, wrong_key)


def test_invisible_text_watermark_missing(valid_pdf):
    wm = InvisibleTextWatermark()

    with pytest.raises(SecretNotFoundError):
        wm.read_secret(
            valid_pdf,
            "test-key-123",
        )
