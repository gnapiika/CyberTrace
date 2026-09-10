import zipfile

from utils.evidence_utils import (
    extract_evidence,
)


def test_extract_evidence(tmp_path):

    # ======================================
    # CREATE FAKE EVIDENCE ZIP
    # ======================================

    zip_path = (
        tmp_path / "evidence.zip"
    )

    with zipfile.ZipFile(
        zip_path,
        "w"
    ) as archive:

        archive.writestr(
            "browser/history.csv",
            (
                "timestamp,url,title\n"
                "2026-09-07,"
                "http://example.com,"
                "Example"
            )
        )

        archive.writestr(
            "authentication/auth.log",
            (
                "2026-09-07 10:00:00 "
                "LOGIN_SUCCESS admin"
            )
        )

        # This file should NOT be extracted
        archive.writestr(
            "malware.exe",
            "fake executable"
        )

    # ======================================
    # EXTRACTION DESTINATION
    # ======================================

    destination = (
        tmp_path / "extracted"
    )

    extracted_files = extract_evidence(
        zip_path,
        destination
    )

    # ======================================
    # VERIFY ALLOWED FILES
    # ======================================

    # Two supported files should be extracted.
    assert len(
        extracted_files
    ) == 2

    # ======================================
    # VERIFY DIRECTORY STRUCTURE
    # ======================================

    assert (
        destination
        / "browser"
        / "history.csv"
    ).exists()

    assert (
        destination
        / "authentication"
        / "auth.log"
    ).exists()

    # ======================================
    # VERIFY UNSUPPORTED FILE
    # ======================================

    assert not (
        destination
        / "malware.exe"
    ).exists()