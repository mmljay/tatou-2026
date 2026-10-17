import base64
import binascii
import hashlib
import hmac
import os

import pymupdf as fitz
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from watermarking_method import (
    InvalidKeyError, SecretNotFoundError, WatermarkingMethod, load_pdf_bytes
)

MARKER = "WM-INVISIBLE-V2:"
CONTEXT = b"wm:invisible-text:v2:aes-gcm"


class InvisibleTextWatermark(WatermarkingMethod):
    name = "invisible-text"

    @staticmethod
    def get_usage():
        return "Encrypts the secret and stores it as non-visible PDF text."

    @staticmethod
    def _key(key):
        if not isinstance(key, str) or not key:
            raise ValueError("Key must not be empty")
        return hmac.new(key.encode(), CONTEXT, hashlib.sha256).digest()

    def add_watermark(self, pdf, secret, key, position=None):
        if not isinstance(secret, str) or not secret:
            raise ValueError("Secret must not be empty")

        nonce = os.urandom(12)
        data = AESGCM(self._key(key)).encrypt(
            nonce, secret.encode(), MARKER.encode()
        )
        token = base64.urlsafe_b64encode(nonce + data).decode()

        with fitz.open(stream=load_pdf_bytes(pdf), filetype="pdf") as doc:
            if not doc.page_count:
                raise ValueError("PDF has no pages")
            page = doc[0]
            page.insert_text(
                fitz.Point(1, max(12, page.rect.height - 12)),
                MARKER + token,
                fontsize=1,
                render_mode=3,
                overlay=False,
            )
            return doc.tobytes(garbage=4, deflate=True)

    def is_watermark_applicable(self, pdf, position=None):
        try:
            with fitz.open(stream=load_pdf_bytes(pdf), filetype="pdf") as doc:
                return doc.page_count > 0 and not doc.needs_pass
        except Exception:
            return False

    def read_secret(self, pdf, key):
        with fitz.open(stream=load_pdf_bytes(pdf), filetype="pdf") as doc:
            text = "".join(page.get_text("text") for page in doc)

        if text.count(MARKER) != 1:
            raise SecretNotFoundError("Watermark missing or duplicated")

        token = text.split(MARKER, 1)[1].split()[0]
        try:
            raw = base64.b64decode(
                token.encode(), altchars=b"-_", validate=True
            )
            secret = AESGCM(self._key(key)).decrypt(
                raw[:12], raw[12:], MARKER.encode()
            )
            return secret.decode()
        except InvalidTag as exc:
            raise InvalidKeyError("Wrong key or changed watermark") from exc
        except (ValueError, UnicodeError, binascii.Error) as exc:
            raise SecretNotFoundError("Invalid watermark data") from exc


__all__ = ["InvisibleTextWatermark"]
