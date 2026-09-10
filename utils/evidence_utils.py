import os
import zipfile


ALLOWED_EXTENSIONS = {
    ".csv",
    ".log",
    ".json",
    ".txt",
}


def extract_evidence(zip_path, destination):
    """
    Safely extract supported forensic evidence files
    from a ZIP archive.

    The original directory structure inside the ZIP
    is preserved so CyberTrace can identify the evidence
    source from its folder.

    Example:

        browser/history.csv
        authentication/auth.log
        files/file_activity.csv

    Unsupported file types are ignored.
    ZIP path traversal is prevented.
    """

    os.makedirs(
        destination,
        exist_ok=True
    )

    extracted_files = []

    destination_path = os.path.abspath(
        destination
    )

    with zipfile.ZipFile(
        zip_path,
        "r"
    ) as archive:

        for member in archive.infolist():

            # Ignore directories
            if member.is_dir():
                continue

            # Get the extension
            extension = os.path.splitext(
                member.filename
            )[1].lower()

            # Ignore unsupported files
            if extension not in ALLOWED_EXTENSIONS:
                continue

            # Normalize the ZIP path
            member_name = os.path.normpath(
                member.filename
            )

            # Prevent absolute paths
            if os.path.isabs(member_name):
                continue

            # Prevent Windows drive paths
            drive, _ = os.path.splitdrive(
                member_name
            )

            if drive:
                continue

            # Build destination path
            target_path = os.path.abspath(
                os.path.join(
                    destination,
                    member_name
                )
            )

            # ZIP path traversal protection
            if not (
                target_path == destination_path
                or target_path.startswith(
                    destination_path + os.sep
                )
            ):
                continue

            # Create parent directory
            parent_directory = os.path.dirname(
                target_path
            )

            os.makedirs(
                parent_directory,
                exist_ok=True
            )

            # Extract file
            with archive.open(member) as source:

                with open(
                    target_path,
                    "wb"
                ) as target:

                    while True:

                        chunk = source.read(
                            8192
                        )

                        if not chunk:
                            break

                        target.write(
                            chunk
                        )

            extracted_files.append(
                target_path
            )

    return extracted_files