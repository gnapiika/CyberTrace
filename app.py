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

from core.evidence_processor import (
    process_evidence,
)

from core.detection_engine import (
    detect_suspicious_activity,
)

from core.alert_manager import (
    save_alerts,
    delete_case_alerts,
    get_case_alerts,
)

from core.risk_engine import (
    calculate_risk_score,
    get_risk_level,
)

from utils.hash_utils import (
    calculate_sha256,
)

from utils.evidence_utils import (
    extract_evidence,
)


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

    cases = get_all_cases()

    open_cases = sum(
        1
        for case in cases
        if case.status == "Open"
    )

    closed_cases = sum(
        1
        for case in cases
        if case.status == "Closed"
    )

    total_events = Event.query.count()

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

    if request.method == "GET":

        return render_template(
            "create_case.html"
        )

    case_name = request.form.get(
        "case_name",
        ""
    ).strip()

    description = request.form.get(
        "description",
        ""
    ).strip()

    if not case_name:

        flash(
            "Case name is required.",
            "error"
        )

        return redirect(
            url_for("create_case_page")
        )

    case = create_case(
        case_name=case_name,
        description=description,
    )

    flash(
        f"Case {case.case_id} created successfully.",
        "success"
    )

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

    case = get_case_by_id(
        case_id
    )

    if case is None:

        flash(
            "Case not found.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    evidence = get_case_evidence(
        case.id
    )

    events = Event.query.filter_by(
        case_id=case.id
    ).order_by(
        Event.timestamp.asc()
    ).all()

    alerts = get_case_alerts(
        case.id
    )

    risk_level = get_risk_level(
        case.risk_score or 0
    )

    return render_template(
        "case_details.html",
        case=case,
        evidence=evidence,
        events=events,
        alerts=alerts,
        risk_level=risk_level,
    )


# ==========================================
# DETERMINE EVIDENCE TYPE
# ==========================================

def detect_evidence_type(
    file_path
):
    """
    Determine the evidence source from
    the directory name inside the ZIP.

    Example:

        browser/history.csv
        -> browser

        authentication/auth.log
        -> authentication
    """

    normalized_path = os.path.normpath(
        file_path
    )

    parts = normalized_path.split(
        os.sep
    )

    supported_types = {
        "browser": "browser",
        "authentication": "authentication",
        "files": "file",
        "usb": "usb",
        "network": "network",
        "processes": "process",
    }

    for part in parts:

        folder_name = part.lower()

        if folder_name in supported_types:

            return supported_types[
                folder_name
            ]

    return None


# ==========================================
# RUN ALERT DETECTION + RISK SCORING
# ==========================================

def analyze_case(
    case
):
    """
    Analyze all events belonging to a case.

    Steps:

        1. Retrieve all case events.
        2. Run detection rules.
        3. Remove previously generated alerts.
        4. Save newly generated alerts.
        5. Calculate risk score.
        6. Update the case.

    Detection is performed across the complete
    investigation rather than only the latest
    evidence file.
    """

    # --------------------------------------
    # GET ALL CASE EVENTS
    # --------------------------------------

    events = Event.query.filter_by(
        case_id=case.id
    ).order_by(
        Event.timestamp.asc()
    ).all()

    # --------------------------------------
    # REMOVE OLD GENERATED ALERTS
    # --------------------------------------

    delete_case_alerts(
        case.id
    )

    # --------------------------------------
    # RUN DETECTION ENGINE
    # --------------------------------------

    alert_data = detect_suspicious_activity(
        events
    )

    # --------------------------------------
    # SAVE GENERATED ALERTS
    # --------------------------------------

    if alert_data:

        save_alerts(
            case_id=case.id,
            alerts=alert_data,
        )

    # --------------------------------------
    # GET SAVED ALERTS
    # --------------------------------------

    saved_alerts = get_case_alerts(
        case.id
    )

    # --------------------------------------
    # CALCULATE RISK SCORE
    # --------------------------------------

    risk_score = calculate_risk_score(
        [
            {
                "severity": alert.severity
            }
            for alert in saved_alerts
        ]
    )

    # --------------------------------------
    # UPDATE CASE
    # --------------------------------------

    case.risk_score = risk_score

    db.session.commit()

    return (
        saved_alerts,
        risk_score,
    )


# ==========================================
# UPLOAD AND PROCESS EVIDENCE
# ==========================================

@app.route(
    "/cases/<case_id>/upload",
    methods=["POST"]
)
def upload_evidence(case_id):

    # --------------------------------------
    # FIND CASE
    # --------------------------------------

    case = get_case_by_id(
        case_id
    )

    if case is None:

        flash(
            "Case not found.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    # --------------------------------------
    # GET FILE
    # --------------------------------------

    uploaded_file = request.files.get(
        "evidence_file"
    )

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
    # CHECK ZIP FILE
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
    # CREATE CASE DIRECTORY
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
    # SAVE ORIGINAL ZIP
    # --------------------------------------

    zip_path = os.path.join(
        case_upload_folder,
        filename
    )

    uploaded_file.save(
        zip_path
    )

    # --------------------------------------
    # CALCULATE SHA-256
    # --------------------------------------

    sha256_hash = calculate_sha256(
        zip_path
    )

    # --------------------------------------
    # CREATE EVIDENCE RECORD
    # --------------------------------------

    evidence = Evidence(

        evidence_id=(
            f"EVD-{uuid.uuid4().hex[:12].upper()}"
        ),

        case_id=case.id,

        filename=filename,

        evidence_type="ZIP",

        file_size=os.path.getsize(
            zip_path
        ),

        sha256_hash=sha256_hash,

        integrity_status="Verified",
    )

    db.session.add(
        evidence
    )

    db.session.commit()

    # --------------------------------------
    # CREATE EXTRACTION DIRECTORY
    # --------------------------------------

    extraction_folder = os.path.join(
        case_upload_folder,
        "extracted"
    )

    try:

        # ----------------------------------
        # EXTRACT ZIP
        # ----------------------------------

        extracted_files = extract_evidence(
            zip_path,
            extraction_folder
        )

        # ----------------------------------
        # PROCESS EACH EVIDENCE FILE
        # ----------------------------------

        processed_count = 0

        skipped_count = 0

        for extracted_file in extracted_files:

            evidence_type = detect_evidence_type(
                extracted_file
            )

            # Unknown source
            if evidence_type is None:

                skipped_count += 1

                continue

            try:

                process_evidence(
                    case_id=case.id,
                    evidence_id=evidence.id,
                    file_path=extracted_file,
                    evidence_type=evidence_type,
                )

                processed_count += 1

            except Exception as parser_error:

                print(
                    "Evidence parser error:",
                    extracted_file,
                    parser_error
                )

                skipped_count += 1

        # ----------------------------------
        # RUN ALERT DETECTION
        # ----------------------------------

        saved_alerts, risk_score = analyze_case(
            case
        )

        # ----------------------------------
        # SUCCESS MESSAGE
        # ----------------------------------

        flash(
            (
                f"Evidence uploaded successfully. "
                f"{processed_count} evidence source(s) "
                f"processed and events stored."
            ),
            "success"
        )

        # ----------------------------------
        # ALERT MESSAGE
        # ----------------------------------

        if saved_alerts:

            flash(
                (
                    f"{len(saved_alerts)} suspicious "
                    f"activity alert(s) detected. "
                    f"Risk score: {risk_score}/100."
                ),
                "error"
            )

        else:

            flash(
                (
                    f"No suspicious activity alerts "
                    f"were detected. Risk score: "
                    f"{risk_score}/100."
                ),
                "success"
            )

        if skipped_count > 0:

            flash(
                (
                    f"{skipped_count} evidence source(s) "
                    f"were skipped or could not be processed."
                ),
                "error"
            )

    except Exception as extraction_error:

        print(
            "Evidence extraction error:",
            extraction_error
        )

        flash(
            (
                "Evidence was uploaded and verified, "
                "but extraction failed."
            ),
            "error"
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