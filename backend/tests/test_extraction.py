"""Unit tests for report text extraction (no network I/O)."""

import pymupdf
import pytest

from app.errors import AnalysisError
from app.services.extraction import (
    MAX_CHARS_DEFAULT,
    extract_text,
    validate_upload,
)


def make_pdf(pages: list[str]) -> bytes:
    doc = pymupdf.open()
    for text in pages:
        page = doc.new_page()
        page.insert_text((72, 72), text)
    return doc.tobytes()


def test_validate_upload_accepts_pdf_and_txt() -> None:
    assert validate_upload("report.pdf", 100) == "pdf"
    assert validate_upload("report.TXT", 100) == "txt"


def test_validate_upload_rejects_bad_type() -> None:
    with pytest.raises(AnalysisError) as exc:
        validate_upload("malware.exe", 100)
    assert exc.value.status_code == 415
    assert exc.value.code == "unsupported_file_type"


def test_validate_upload_rejects_oversize() -> None:
    with pytest.raises(AnalysisError) as exc:
        validate_upload("big.pdf", 10 * 1024 * 1024 + 1)
    assert exc.value.status_code == 413
    assert exc.value.code == "file_too_large"


def test_validate_upload_rejects_empty() -> None:
    with pytest.raises(AnalysisError) as exc:
        validate_upload("empty.txt", 0)
    assert exc.value.status_code == 400
    assert exc.value.code == "empty_file"


def test_extract_txt_utf8() -> None:
    extracted = extract_text("ping 192.0.2.44\n".encode(), "txt")
    assert "192.0.2.44" in extracted.text
    assert extracted.truncated is False


def test_extract_txt_latin1_fallback() -> None:
    extracted = extract_text("caf\xe9 alerts\n".encode("latin-1"), "txt")
    assert "café" in extracted.text


def test_extract_pdf_multipage() -> None:
    data = make_pdf(["first page marker ALPHA", "second page marker BETA"])
    extracted = extract_text(data, "pdf")
    assert "ALPHA" in extracted.text
    assert "BETA" in extracted.text


def test_extract_pdf_rejects_garbage() -> None:
    with pytest.raises(AnalysisError) as exc:
        extract_text(b"%PDF-1.4 not really a pdf \x00\x01", "pdf")
    assert exc.value.status_code == 400


def test_extract_pdf_rejects_encrypted() -> None:
    doc = pymupdf.open()
    doc.new_page().insert_text((72, 72), "secret")
    data = doc.tobytes(
        encryption=pymupdf.PDF_ENCRYPT_AES_256, owner_pw="owner", user_pw="user"
    )
    with pytest.raises(AnalysisError) as exc:
        extract_text(data, "pdf")
    assert exc.value.code == "encrypted_pdf"


def test_extract_pdf_rejects_no_text() -> None:
    doc = pymupdf.open()
    doc.new_page()  # blank page, no text
    with pytest.raises(AnalysisError) as exc:
        extract_text(doc.tobytes(), "pdf")
    assert exc.value.code == "no_extractable_text"


def test_extract_truncates_long_reports() -> None:
    extracted = extract_text(b"x" * (MAX_CHARS_DEFAULT + 5000), "txt")
    assert extracted.truncated is True
    assert len(extracted.text) <= MAX_CHARS_DEFAULT
