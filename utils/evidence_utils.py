import os
import zipfile


ALLOWED_EXTENSIONS = {
    ".csv",
    ".log",
    ".json",
    ".txt",
}


def extract_evidence(zip_path, destination):
    os.makedirs(destination, exist_ok=True)

    extracted_files = []

    with zipfile.ZipFile(zip_path, "r") as archive:

        for member in archive.infolist():

            # Ignore directories
            if member.is_dir():
                continue

            # Get only the filename, not the directory structure
            filename = os.path.basename(member.filename)

            if not filename:
                continue

            # Check file extension
            extension = os.path.splitext(filename)[1].lower()

            if extension not in ALLOWED_EXTENSIONS:
                continue

            # Build the destination path
            target_path = os.path.abspath(
                os.path.join(destination, filename)
            )

            # Security check: prevent ZIP path traversal
            destination_path = os.path.abspath(destination)

            if not target_path.startswith(destination_path + os.sep):
                continue

            # Extract the file
            with archive.open(member) as source:
                with open(target_path, "wb") as target:
                    target.write(source.read())

            extracted_files.append(target_path)

    return extracted_files