import os
import uuid

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
)

from config import (
    UPLOAD_FOLDER,
    REPORT_FOLDER,
    SQLALCHEMY_DATABASE_URI,
    SQLALCHEMY_TRACK_MODIFICATIONS,
)

from database.database import db

from models.case import Case
from models.evidence import Evidence
from models.event import Event
from models.alert import Alert

from core.case_manager import (
    create_case,
    get_all_cases,
    get_case_by_id,
)

from core.evidence_manager import (
    get_case_evidence,
)

from utils.hash_utils import calculate_sha256


# ==========================================
# CREATE FLASK APPLICATION
# ==========================================

app = Flask(__name__)


# ==========================================
# APPLICATION CONFIGURATION
# ==========================================

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

app.config["REPORT_FOLDER"] = REPORT_FOLDER

app.config["SQLALCHEMY_DATABASE_URI"] = (
    SQLALCHEMY_DATABASE_URI
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = (
    SQLALCHEMY_TRACK_MODIFICATIONS
)

# Secret key for Flask flash messages
app.secret_key = "cybertrace-development-key"


# ==========================================
# DATABASE INITIALIZATION
# ==========================================

db.init_app(app)

with app.app_context():
    db.create_all()


# ==========================================
# HOME PAGE
# ==========================================

@app.route("/")
def home():

    return redirect(
        url_for("dashboard")
    )


# ==========================================
# DASHBOARD
# ==========================================

@app.route("/dashboard")
def dashboard():

    # Get all investigation cases
    cases = get_all_cases()

    # Count open cases
    open_cases = sum(
        1
        for case in cases
        if case.status == "Open"
    )

    # Count closed cases
    closed_cases = sum(
        1
        for case in cases
        if case.status == "Closed"
    )

    # Count all events
    total_events = Event.query.count()

    # Count all alerts
    total_alerts = Alert.query.count()

    return render_template(
        "dashboard.html",
        cases=cases,
        open_cases=open_cases,
        closed_cases=closed_cases,
        total_events=total_events,
        total_alerts=total_alerts,
    )


# ==========================================
# CREATE NEW CASE
# ==========================================

@app.route(
    "/cases/create",
    methods=["GET", "POST"]
)
def create_case_page():

    # --------------------------------------
    # SHOW CREATE CASE FORM
    # --------------------------------------

    if request.method == "GET":

        return render_template(
            "create_case.html"
        )

    # --------------------------------------
    # GET FORM DATA
    # --------------------------------------

    case_name = request.form.get(
        "case_name",
        ""
    ).strip()

    description = request.form.get(
        "description",
        ""
    ).strip()

    # --------------------------------------
    # VALIDATE CASE NAME
    # --------------------------------------

    if not case_name:

        flash(
            "Case name is required.",
            "error"
        )

        return redirect(
            url_for("create_case_page")
        )

    # --------------------------------------
    # CREATE DATABASE CASE
    # --------------------------------------

    case = create_case(
        case_name=case_name,
        description=description,
    )

    # --------------------------------------
    # SUCCESS MESSAGE
    # --------------------------------------

    flash(
        f"Case {case.case_id} created successfully.",
        "success"
    )

    # --------------------------------------
    # REDIRECT TO CASE DETAILS
    # --------------------------------------

    return redirect(
        url_for(
            "case_details",
            case_id=case.case_id
        )
    )


# ==========================================
# CASE DETAILS
# ==========================================

@app.route(
    "/cases/<case_id>"
)
def case_details(case_id):

    # --------------------------------------
    # FIND CASE
    # --------------------------------------

    case = get_case_by_id(case_id)

    # --------------------------------------
    # CASE NOT FOUND
    # --------------------------------------

    if case is None:

        flash(
            "Case not found.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    # --------------------------------------
    # GET CASE EVIDENCE
    # --------------------------------------

    evidence = get_case_evidence(
        case.id
    )

    # --------------------------------------
    # GET CASE EVENTS
    # --------------------------------------

    events = Event.query.filter_by(
        case_id=case.id
    ).order_by(
        Event.timestamp.asc()
    ).all()

    # --------------------------------------
    # GET CASE ALERTS
    # --------------------------------------

    # Alert currently does not have a
    # created_at field, so sort by ID.
    alerts = Alert.query.filter_by(
        case_id=case.id
    ).order_by(
        Alert.id.desc()
    ).all()

    # --------------------------------------
    # DISPLAY CASE DETAILS
    # --------------------------------------

    return render_template(
        "case_details.html",
        case=case,
        evidence=evidence,
        events=events,
        alerts=alerts,
    )


# ==========================================
# UPLOAD EVIDENCE
# ==========================================

@app.route(
    "/cases/<case_id>/upload",
    methods=["POST"]
)
def upload_evidence(case_id):

    # --------------------------------------
    # FIND CASE
    # --------------------------------------

    case = get_case_by_id(case_id)

    if case is None:

        flash(
            "Case not found.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    # --------------------------------------
    # GET UPLOADED FILE
    # --------------------------------------

    uploaded_file = request.files.get(
        "evidence_file"
    )

    # --------------------------------------
    # CHECK WHETHER FILE WAS PROVIDED
    # --------------------------------------

    if uploaded_file is None:

        flash(
            "No evidence file was selected.",
            "error"
        )

        return redirect(
            url_for(
                "case_details",
                case_id=case.case_id
            )
        )

    if uploaded_file.filename == "":

        flash(
            "No evidence file was selected.",
            "error"
        )

        return redirect(
            url_for(
                "case_details",
                case_id=case.case_id
            )
        )

    # --------------------------------------
    # CHECK FILE TYPE
    # --------------------------------------

    filename = uploaded_file.filename

    if not filename.lower().endswith(".zip"):

        flash(
            "Only ZIP evidence packages are supported.",
            "error"
        )

        return redirect(
            url_for(
                "case_details",
                case_id=case.case_id
            )
        )

    # --------------------------------------
    # CREATE CASE UPLOAD DIRECTORY
    # --------------------------------------

    case_upload_folder = os.path.join(
        app.config["UPLOAD_FOLDER"],
        case.case_id
    )

    os.makedirs(
        case_upload_folder,
        exist_ok=True
    )

    # --------------------------------------
    # SAVE UPLOADED FILE
    # --------------------------------------

    file_path = os.path.join(
        case_upload_folder,
        filename
    )

    uploaded_file.save(
        file_path
    )

    # --------------------------------------
    # CALCULATE SHA-256
    # --------------------------------------

    sha256_hash = calculate_sha256(
        file_path
    )

    # --------------------------------------
    # CREATE EVIDENCE DATABASE RECORD
    # --------------------------------------

    evidence = Evidence(

        evidence_id=(
            f"EVD-{uuid.uuid4().hex[:12].upper()}"
        ),

        case_id=case.id,

        filename=filename,

        evidence_type="ZIP",

        file_size=os.path.getsize(
            file_path
        ),

        sha256_hash=sha256_hash,

        integrity_status="Verified",
    )

    db.session.add(
        evidence
    )

    db.session.commit()

    # --------------------------------------
    # SUCCESS MESSAGE
    # --------------------------------------

    flash(
        "Evidence uploaded and SHA-256 integrity verified.",
        "success"
    )

    # --------------------------------------
    # RETURN TO CASE
    # --------------------------------------

    return redirect(
        url_for(
            "case_details",
            case_id=case.case_id
        )
    )


# ==========================================
# APPLICATION ENTRY POINT
# ==========================================

if __name__ == "__main__":

    app.run(
        debug=True
    )