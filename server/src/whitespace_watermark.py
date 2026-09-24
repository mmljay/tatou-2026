from __future__ import annotations

import io
from typing import Any


class WhitespaceWatermark:
    """A simple whitespace-based watermarking method for PDF-like bytes."""

    def add_watermark(self, pdf_data: bytes, secret: str, key: str) -> bytes:
        marker = self._encode_marker(secret, key)
        payload = b"\x00" + marker
        return pdf_data + payload

    def read_secret(self, pdf_data: bytes, key: str) -> str:
        payload = pdf_data.split(b"\x00")[-1]
        if not payload:
            raise ValueError("No watermark payload found")
        return self._decode_marker(payload, key)

    def _encode_marker(self, secret: str, key: str) -> bytes:
        if not secret:
            return b""
        return f"{secret}:{key}".encode("utf-8")

    def _decode_marker(self, payload: bytes, key: str) -> str:
        decoded = payload.decode("utf-8", errors="strict")
        if not decoded:
            raise ValueError("Empty watermark payload")
        if ":" not in decoded:
            raise ValueError("Invalid watermark payload")
        secret, actual_key = decoded.rsplit(":", 1)
        if actual_key != key:
            raise ValueError("Key mismatch")
        return secret
