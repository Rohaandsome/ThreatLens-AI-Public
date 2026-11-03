"""Report upload validation and text extraction.

Uploaded content is treated as untrusted data: it is only ever parsed as
text in memory. Filenames are never used for filesystem access and nothing
from an upload is executed.
"""

from dataclasses import dataclass
from typing import Literal

import pymupdf

from ..errors import AnalysisError

FileType = Literal["pdf", "txt"]

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_CHARS_DEFAULT = 60000

@dataclass(frozen=True)
class ExtractedReport:
    text: str
    char_count: int
    truncated: bool


def validate_upload(filename: str | None, size: int) -> FileType:
    """Validate size/type; returns the file type or raises AnalysisError."""
    if size is not None and size > MAX_UPLOAD_BYTES:
        raise AnalysisError(
            413, "file_too_large", "File exceeds the 10 MB limit."
        )
    if size == 0:
        raise AnalysisError(400, "empty_file", "File is empty.")
    lower = (filename or "").lower()
    if lower.endswith(".pdf"):
        return "pdf"
    if lower.endswith(".txt"):
        return "txt"
    raise AnalysisError(
        415,
        "unsupported_file_type",
        "Only PDF and TXT reports are accepted.",
    )


def extract_text(data: bytes, file_type: FileType, max_chars: int = MAX_CHARS_DEFAULT) -> ExtractedReport:
    """Extract plain text from raw upload bytes."""
    if not data:
        raise AnalysisError(400, "empty_file", "File is empty.")
    if file_type == "txt":
        text = _decode_text(data)
    else:
        text = _extract_pdf(data)
    text = text.strip()
    if not text:
        raise AnalysisError(
            400, "no_extractable_text", "No readable text found in the file."
        )
    char_count = len(text)
    if char_count > max_chars:
        return ExtractedReport(
            text=text[:max_chars], char_count=char_count, truncated=True
        )
    return ExtractedReport(text=text, char_count=char_count, truncated=False)


def _decode_text(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def _extract_pdf(data: bytes) -> str:
    try:
        doc = pymupdf.open(stream=data, filetype="pdf")
    except Exception as exc:
        raise AnalysisError(
            400, "unreadable_pdf", "File is not a readable PDF."
        ) from exc
    with doc:
        if doc.is_encrypted:
            raise AnalysisError(
                400,
                "encrypted_pdf",
                "Encrypted PDFs are not supported; upload an unprotected copy.",
            )
        parts = [page.get_text() for page in doc]
    return "\n".join(part for part in parts if part.strip())
