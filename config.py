import os


BASE_DIR = os.path.abspath(
    os.path.dirname(__file__)
)


# ==========================================
# DATABASE
# ==========================================

DATABASE_URL = os.environ.get(
    "DATABASE_URL"
)

if DATABASE_URL:
    # Railway may provide postgres://
    # SQLAlchemy expects postgresql://
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace(
            "postgres://",
            "postgresql://",
            1
        )

    SQLALCHEMY_DATABASE_URI = DATABASE_URL

else:
    DATABASE_PATH = os.path.join(
        BASE_DIR,
        "database",
        "cybertrace.db"
    )

    SQLALCHEMY_DATABASE_URI = (
        f"sqlite:///{DATABASE_PATH}"
    )


SQLALCHEMY_TRACK_MODIFICATIONS = False


# ==========================================
# FILE STORAGE
# ==========================================

UPLOAD_FOLDER = os.environ.get(
    "UPLOAD_FOLDER",
    os.path.join(
        BASE_DIR,
        "uploads"
    )
)

REPORT_FOLDER = os.environ.get(
    "REPORT_FOLDER",
    os.path.join(
        BASE_DIR,
        "reports"
    )
)


# ==========================================
# APPLICATION
# ==========================================

SECRET_KEY = os.environ.get(
    "SECRET_KEY",
    "cybertrace-development-key"
)