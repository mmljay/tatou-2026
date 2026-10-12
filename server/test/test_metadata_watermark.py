import pymupdf
import pytest

from metadata_watermark import MetadataWatermark
from watermarking_method import InvalidKeyError, SecretNotFoundError


@pytest.fixture
def valid_pdf():
    document = pymupdf.open()
    document.new_page()
    pdf_bytes = document.tobytes()
    document.close()
    return pdf_bytes


def test_metadata_watermark_round_trip(valid_pdf):
    wm = MetadataWatermark()
    secret = "Phase I metadata watermark test"
    key = "test-key-123"

    assert wm.is_watermark_applicable(valid_pdf)

    watermarked = wm.add_watermark(valid_pdf, secret, key)

    assert wm.read_secret(watermarked, key) == secret


def test_metadata_watermark_wrong_key(valid_pdf):
    wm = MetadataWatermark()
    watermarked = wm.add_watermark(
        valid_pdf, "Protected secret", "correct-key"
    )

    with pytest.raises(InvalidKeyError):
        wm.read_secret(watermarked, "wrong-key")


def test_metadata_watermark_missing_secret(valid_pdf):
    wm = MetadataWatermark()

    with pytest.raises(SecretNotFoundError):
        wm.read_secret(valid_pdf, "test-key-123")
