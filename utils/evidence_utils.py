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
    Safely extract supported forensic evidence files from a ZIP archive.

    The original directory structure inside the ZIP is preserved so that
    CyberTrace can identify the evidence source from its parent directory.

    Only supported evidence file types are extracted.
    """

    os.makedirs(destination, exist_ok=True)

    extracted_files = []

    destination = os.path.abspath(destination)

    with zipfile.ZipFile(zip_path, "r") as archive:

        for member in archive.infolist():

            # Ignore directories.
            if member.is_dir():
                continue

            original_path = member.filename

            # Normalize ZIP path separators.
            normalized_path = original_path.replace("/", os.sep)

            # Remove unsafe path components.
            safe_parts = []

            for part in normalized_path.split(os.sep):

                if not part or part == ".":
                    continue

                if part == "..":
                    continue

                safe_parts.append(part)

            if not safe_parts:
                continue

            safe_relative_path = os.path.join(
                *safe_parts
            )

            filename = safe_parts[-1]

            extension = os.path.splitext(
                filename
            )[1].lower()

            # Only extract supported evidence formats.
            if extension not in ALLOWED_EXTENSIONS:
                continue

            target_path = os.path.abspath(
                os.path.join(
                    destination,
                    safe_relative_path,
                )
            )

            # Prevent path traversal outside extraction directory.
            if not target_path.startswith(
                destination + os.sep
            ):
                continue

            target_directory = os.path.dirname(
                target_path
            )

            os.makedirs(
                target_directory,
                exist_ok=True,
            )

            with archive.open(member) as source:

                with open(
                    target_path,
                    "wb",
                ) as target:

                    while True:

                        chunk = source.read(8192)

                        if not chunk:
                            break

                        target.write(chunk)

            extracted_files.append(
                target_path
            )

    return extracted_files