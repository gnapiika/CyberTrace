from parsers.browser_parser import parse_browser_history
from parsers.auth_parser import parse_auth_log
from parsers.file_parser import parse_file_activity
from parsers.usb_parser import parse_usb_activity
from parsers.network_parser import parse_network_activity
from parsers.process_parser import parse_process_activity

from core.event_ingestor import save_events


PARSER_MAP = {
    "browser": parse_browser_history,
    "authentication": parse_auth_log,
    "file": parse_file_activity,
    "usb": parse_usb_activity,
    "network": parse_network_activity,
    "process": parse_process_activity,
}


def process_evidence(
    case_id,
    evidence_id,
    file_path,
    evidence_type,
):
    evidence_type = evidence_type.lower().strip()

    if evidence_type not in PARSER_MAP:
        raise ValueError(
            f"Unsupported evidence type: {evidence_type}"
        )

    parser = PARSER_MAP[evidence_type]

    events = parser(file_path)

    saved_events = save_events(
        case_id=case_id,
        evidence_id=evidence_id,
        events=events,
    )

    return saved_events