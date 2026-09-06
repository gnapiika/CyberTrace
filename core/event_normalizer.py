from datetime import datetime


def normalize_event(
    event_type,
    timestamp,
    description,
    username=None,
    source_ip=None,
    destination_ip=None,
    severity="INFO",
    raw_data=None,
):
    if isinstance(timestamp, str):
        timestamp = datetime.fromisoformat(timestamp)

    return {
        "event_type": event_type,
        "timestamp": timestamp,
        "description": description,
        "username": username,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "severity": severity,
        "raw_data": raw_data,
    }