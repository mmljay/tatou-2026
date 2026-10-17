"""Toy watermarking method that appends a secret after the PDF EOF marker."""

from __future__ import annotations

from typing import Final

from watermarking_method import (
    SecretNotFoundError,
    WatermarkingMethod,
    load_pdf_bytes,
)


class UnsafeBashBridgeAppendEOF(WatermarkingMethod):
    """Toy method that appends a watermark record after the PDF EOF."""

    name: Final[str] = "bash-bridge-eof"

    @staticmethod
    def get_usage() -> str:
        return (
            "Toy method that appends a watermark record after the PDF EOF. "
            "Position and key are ignored."
        )

    def add_watermark(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended."""

        data = load_pdf_bytes(pdf)
        return data + secret.encode("utf-8")

    def is_watermark_applicable(
        self,
        pdf,
        position: str | None = None,
    ) -> bool:
        return True

    def read_secret(self, pdf, key: str) -> str:
        """Extract the secret appended after the PDF EOF marker."""

        data = load_pdf_bytes(pdf)
        marker = b"%%EOF"
        eof_position = data.rfind(marker)

        if eof_position == -1:
            raise SecretNotFoundError("PDF EOF marker not found")

        payload = data[eof_position + len(marker):]
        return payload.decode("utf-8").strip()


__all__ = ["UnsafeBashBridgeAppendEOF"]
