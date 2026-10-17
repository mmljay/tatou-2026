"""AES-GCM recipient watermark stored in PDF XMP metadata."""

import base64
import binascii
import hashlib
import os
import xml.etree.ElementTree as ET

import pymupdf as fitz
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from watermarking_method import (
    InvalidKeyError,
    SecretNotFoundError,
    WatermarkingMethod,
    load_pdf_bytes,
)

XMP_NS = "adobe:ns:meta/"
RDF_NS = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
WM_NS = "https://tatou.example/watermark/1.0/"
MARKER = f"{{{WM_NS}}}WM_METADATA_V1"
NONCE_SIZE = 12
TAG_SIZE = 16

ET.register_namespace("x", XMP_NS)
ET.register_namespace("rdf", RDF_NS)
ET.register_namespace("tatou", WM_NS)


class MetadataWatermark(WatermarkingMethod):
    name = "metadata-watermark"

    @staticmethod
    def get_usage() -> str:
        return "Encrypt a recipient secret with AES-256-GCM in PDF XMP metadata."

    @staticmethod
    def _key_bytes(key: str) -> bytes:
        if not isinstance(key, str) or not key:
            raise InvalidKeyError("A nonempty string key is required.")
        return hashlib.sha256(key.encode("utf-8")).digest()

    @classmethod
    def _encrypt(cls, secret: str, key: str) -> str:
        if not isinstance(secret, str):
            raise TypeError("Secret must be a string.")

        aes_key = cls._key_bytes(key)
        nonce = os.urandom(NONCE_SIZE)
        encrypted = AESGCM(aes_key).encrypt(
            nonce, secret.encode("utf-8"), None
        )
        return base64.b64encode(nonce + encrypted).decode("ascii")

    @classmethod
    def _decrypt(cls, payload: str, key: str) -> str:
        aes_key = cls._key_bytes(key)

        try:
            raw = base64.b64decode(payload.encode("ascii"), validate=True)
        except (ValueError, UnicodeEncodeError, binascii.Error) as exc:
            raise SecretNotFoundError("Malformed watermark payload.") from exc

        if len(raw) < NONCE_SIZE + TAG_SIZE:
            raise SecretNotFoundError("Incomplete watermark payload.")

        try:
            plain = AESGCM(aes_key).decrypt(
                raw[:NONCE_SIZE], raw[NONCE_SIZE:], None
            )
        except InvalidTag as exc:
            raise InvalidKeyError(
                "Wrong key or modified watermark payload."
            ) from exc

        try:
            return plain.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SecretNotFoundError(
                "Decrypted secret is not UTF-8."
            ) from exc

    @staticmethod
    def _xmp_root(xmp: str) -> ET.Element:
        if not xmp:
            root = ET.Element(f"{{{XMP_NS}}}xmpmeta")
            ET.SubElement(root, f"{{{RDF_NS}}}RDF")
            return root

        try:
            root = ET.fromstring(xmp)
        except ET.ParseError as exc:
            raise ValueError("Existing XMP metadata is malformed.") from exc

        if root.tag != f"{{{XMP_NS}}}xmpmeta":
            raise ValueError(
                "Existing XMP metadata has an unsupported root."
            )
        return root

    @classmethod
    def _set_payload(cls, xmp: str, payload: str) -> str:
        root = cls._xmp_root(xmp)
        rdf = root.find(f"{{{RDF_NS}}}RDF")

        if rdf is None:
            rdf = ET.SubElement(root, f"{{{RDF_NS}}}RDF")

        for description in rdf.findall(f"{{{RDF_NS}}}Description"):
            for old in description.findall(MARKER):
                description.remove(old)

        description = ET.SubElement(
            rdf, f"{{{RDF_NS}}}Description"
        )
        description.set(f"{{{RDF_NS}}}about", "")
        ET.SubElement(description, MARKER).text = payload

        return ET.tostring(root, encoding="unicode")

    @classmethod
    def _get_payload(cls, xmp: str) -> str:
        if not xmp:
            raise SecretNotFoundError("No XMP metadata in PDF.")

        try:
            root = cls._xmp_root(xmp)
        except ValueError as exc:
            raise SecretNotFoundError(
                "Malformed XMP metadata."
            ) from exc

        entries = root.findall(f".//{MARKER}")
        if len(entries) != 1 or not entries[0].text:
            raise SecretNotFoundError(
                "Metadata watermark missing or ambiguous."
            )

        return entries[0].text.strip()

    def add_watermark(
        self, pdf, secret: str, key: str, position=None
    ) -> bytes:
        payload = self._encrypt(secret, key)
        data = load_pdf_bytes(pdf)

        with fitz.open(stream=data, filetype="pdf") as document:
            xmp = self._set_payload(
                document.get_xml_metadata(), payload
            )
            document.set_xml_metadata(xmp)
            return document.tobytes(garbage=4, deflate=True)

    def read_secret(self, pdf, key: str) -> str:
        self._key_bytes(key)
        data = load_pdf_bytes(pdf)

        with fitz.open(stream=data, filetype="pdf") as document:
            payload = self._get_payload(
                document.get_xml_metadata()
            )
            return self._decrypt(payload, key)

    def is_watermark_applicable(
        self, pdf, position=None
    ) -> bool:
        try:
            data = load_pdf_bytes(pdf)
            with fitz.open(
                stream=data, filetype="pdf"
            ) as document:
                self._xmp_root(document.get_xml_metadata())
                return bool(
                    document.is_pdf
                    and document.page_count > 0
                     and not document.needs_pass )
        except (OSError, ValueError, TypeError, RuntimeError):
            return False


__all__ = ["MetadataWatermark"]
