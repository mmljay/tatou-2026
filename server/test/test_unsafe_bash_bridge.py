import fitz
import pytest

from unsafe_bash_bridge_append_eof import UnsafeBashBridgeAppendEOF
from watermarking_method import SecretNotFoundError


@pytest.fixture
def sample_pdf(tmp_path):
    path = tmp_path / "sample.pdf"
    with fitz.open() as doc:
        doc.new_page()
        doc.save(path)
    return path


def test_watermark_roundtrip(sample_pdf, tmp_path):
    method = UnsafeBashBridgeAppendEOF()
    secret = "ordinary-test-secret"

    result = method.add_watermark(sample_pdf, secret, key="ignored-key")
    output = tmp_path / "watermarked.pdf"
    output.write_bytes(result)

    assert method.read_secret(output, key="ignored-key") == secret


def test_shell_metacharacters_are_plain_text(sample_pdf, tmp_path):
    method = UnsafeBashBridgeAppendEOF()
    secret = "$(touch /tmp/tatou-bridge-test-marker); `id`"

    result = method.add_watermark(sample_pdf, secret, key="ignored-key")
    output = tmp_path / "watermarked.pdf"
    output.write_bytes(result)

    assert method.read_secret(output, key="ignored-key") == secret
    assert not __import__("pathlib").Path(
        "/tmp/tatou-bridge-test-marker"
    ).exists()


def test_missing_eof_marker_raises(sample_pdf, tmp_path):
    method = UnsafeBashBridgeAppendEOF()
    data = sample_pdf.read_bytes()
    data = data[:data.rfind(b"%%EOF")]
    output = tmp_path / "missing-eof.pdf"
    output.write_bytes(data)

    with pytest.raises(SecretNotFoundError):
        method.read_secret(output, key="ignored-key")
