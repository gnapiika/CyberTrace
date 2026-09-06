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

            if member.is_dir():
                continue

            filename = os.path.basename(member.filename)

            if not filename:
                continue

            extension = os.path.splitext(filename)[1].lower()

            if extension not in ALLOWED_EXTENSIONS:
                continue

            target_path = os.path.join(destination, filename)

            with archive.open(member) as source:
                with open(target_path, "wb") as target:
                    target.write(source.read())

            extracted_files.append(target_path)

    return extracted_files