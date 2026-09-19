import os
import shutil
import uuid

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    send_file,
)

from config import (
    UPLOAD_FOLDER,
    REPORT_FOLDER,
    SQLALCHEMY_DATABASE_URI,
    SQLALCHEMY_TRACK_MODIFICATIONS,
    SECRET_KEY,
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

from core.correlation_engine import (
    correlate_events,
)

from core.report_generator import (
    generate_investigation_report,
)

from utils.hash_utils import (
    calculate_sha256,
)

from utils.evidence_utils import (
    extract_evidence,
)


app = Flask(__name__)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["REPORT_FOLDER"] = REPORT_FOLDER
app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = (
    SQLALCHEMY_TRACK_MODIFICATIONS
)

app.secret_key = SECRET_KEY

db.init_app(app)


with app.app_context():
    db.create_all()


@app.route("/")
def home():
    return redirect(
        url_for("dashboard")
    )


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

    events = (
        Event.query
        .filter_by(case_id=case.id)
        .order_by(Event.timestamp.asc())
        .all()
    )

    alerts = get_case_alerts(
        case.id
    )

    correlations = correlate_events(
        events
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
        correlations=correlations,
        risk_level=risk_level,
    )


def detect_evidence_type(file_path):

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


def analyze_case(case):

    events = (
        Event.query
        .filter_by(case_id=case.id)
        .order_by(Event.timestamp.asc())
        .all()
    )

    delete_case_alerts(
        case.id
    )

    alert_data = detect_suspicious_activity(
        events
    )

    if alert_data:

        save_alerts(
            case_id=case.id,
            alerts=alert_data,
        )

    correlations = correlate_events(
        events
    )

    saved_alerts = get_case_alerts(
        case.id
    )

    risk_score = calculate_risk_score(
        [
            {
                "severity": alert.severity,
                "rule_id": alert.rule_id,
            }
            for alert in saved_alerts
        ]
    )

    case.risk_score = risk_score

    db.session.commit()

    return (
        saved_alerts,
        risk_score,
        correlations,
    )


@app.route(
    "/cases/<case_id>/upload",
    methods=["POST"]
)
def upload_evidence(case_id):

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

    case_upload_folder = os.path.join(
        app.config["UPLOAD_FOLDER"],
        case.case_id,
    )

    os.makedirs(
        case_upload_folder,
        exist_ok=True,
    )

    zip_path = os.path.join(
        case_upload_folder,
        filename,
    )

    uploaded_file.save(
        zip_path
    )

    sha256_hash = calculate_sha256(
        zip_path
    )

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

    extraction_folder = os.path.join(
        case_upload_folder,
        "extracted",
    )

    try:

        extracted_files = extract_evidence(
            zip_path,
            extraction_folder,
        )

        processed_count = 0
        skipped_count = 0

        for extracted_file in extracted_files:

            evidence_type = detect_evidence_type(
                extracted_file
            )

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
                    parser_error,
                )

                skipped_count += 1

        (
            saved_alerts,
            risk_score,
            correlations,
        ) = analyze_case(
            case
        )

        flash(
            (
                "Evidence uploaded successfully. "
                f"{processed_count} evidence source(s) "
                "processed and events stored."
            ),
            "success",
        )

        if saved_alerts:

            flash(
                (
                    f"{len(saved_alerts)} suspicious "
                    "activity alert(s) detected. "
                    f"Risk score: {risk_score}/100."
                ),
                "error",
            )

        else:

            flash(
                (
                    "No suspicious activity alerts "
                    "were detected. "
                    f"Risk score: {risk_score}/100."
                ),
                "success",
            )

        if correlations:

            flash(
                (
                    f"{len(correlations)} correlated "
                    "activity group(s) identified."
                ),
                "success",
            )

        if skipped_count > 0:

            flash(
                (
                    f"{skipped_count} evidence source(s) "
                    "were skipped or could not be processed."
                ),
                "error",
            )

    except Exception as extraction_error:

        print(
            "Evidence extraction error:",
            extraction_error,
        )

        flash(
            (
                "Evidence was uploaded and verified, "
                "but extraction failed."
            ),
            "error",
        )

    return redirect(
        url_for(
            "case_details",
            case_id=case.case_id
        )
    )


@app.route(
    "/cases/<case_id>/delete",
    methods=["POST"]
)
def delete_case(case_id):

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

    case_identifier = case.case_id

    try:

        # Delete alerts
        Alert.query.filter_by(
            case_id=case.id
        ).delete(
            synchronize_session=False
        )

        # Delete events
        Event.query.filter_by(
            case_id=case.id
        ).delete(
            synchronize_session=False
        )

        # Delete evidence records
        Evidence.query.filter_by(
            case_id=case.id
        ).delete(
            synchronize_session=False
        )

        # Delete the case itself
        db.session.delete(
            case
        )

        db.session.commit()

        # Delete uploaded evidence directory
        case_upload_folder = os.path.join(
            app.config["UPLOAD_FOLDER"],
            case_identifier,
        )

        if os.path.exists(
            case_upload_folder
        ):

            shutil.rmtree(
                case_upload_folder
            )

        # Delete generated report
        report_filename = (
            f"{case_identifier}_investigation_report.pdf"
        )

        report_path = os.path.join(
            app.config["REPORT_FOLDER"],
            report_filename,
        )

        if os.path.exists(
            report_path
        ):

            os.remove(
                report_path
            )

        flash(
            f"Case {case_identifier} was deleted successfully.",
            "success"
        )

    except Exception as delete_error:

        db.session.rollback()

        print(
            "Case deletion error:",
            delete_error,
        )

        flash(
            "Failed to delete the case.",
            "error"
        )

    return redirect(
        url_for("dashboard")
    )


@app.route(
    "/cases/<case_id>/report"
)
def generate_report(case_id):

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

    events = (
        Event.query
        .filter_by(case_id=case.id)
        .order_by(Event.timestamp.asc())
        .all()
    )

    alerts = get_case_alerts(
        case.id
    )

    correlations = correlate_events(
        events
    )

    risk_score = case.risk_score or 0

    risk_level = get_risk_level(
        risk_score
    )

    report_filename = (
        f"{case.case_id}_investigation_report.pdf"
    )

    os.makedirs(
        app.config["REPORT_FOLDER"],
        exist_ok=True,
    )

    report_path = os.path.join(
        app.config["REPORT_FOLDER"],
        report_filename,
    )

    try:

        generate_investigation_report(
            case=case,
            evidence=evidence,
            events=events,
            alerts=alerts,
            risk_score=risk_score,
            risk_level=risk_level,
            output_path=report_path,
            correlations=correlations,
        )

        flash(
            "Investigation report generated successfully.",
            "success"
        )

        return send_file(
            report_path,
            as_attachment=True,
            download_name=report_filename,
            mimetype="application/pdf",
        )

    except Exception as report_error:

        print(
            "Report generation error:",
            report_error,
        )

        flash(
            "Failed to generate the investigation report.",
            "error"
        )

        return redirect(
            url_for(
                "case_details",
                case_id=case.case_id
            )
        )


if __name__ == "__main__":

    app.run(
        debug=True
    )