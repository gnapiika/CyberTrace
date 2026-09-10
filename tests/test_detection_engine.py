from datetime import datetime, timedelta

from models.event import Event

from core.detection_engine import (
    detect_suspicious_activity,
)


def make_event(
    event_id,
    event_type,
    timestamp,
    description,
    username=None,
    source_ip=None,
):
    return Event(
        event_id=event_id,
        case_id=1,
        event_type=event_type,
        timestamp=datetime.fromisoformat(
            timestamp
        ),
        description=description,
        username=username,
        source_ip=source_ip,
        severity="INFO",
        raw_data=description,
    )


# ==========================================
# BRUTE FORCE TEST
# ==========================================

def test_brute_force_detection():

    events = []

    start_time = datetime(
        2026,
        9,
        7,
        9,
        58,
        0,
    )

    for index in range(5):

        timestamp = (
            start_time
            + timedelta(minutes=index)
        )

        events.append(
            make_event(
                event_id=f"FAIL-{index}",
                event_type="authentication",
                timestamp=timestamp.isoformat(),
                description=(
                    "Failed login attempt for "
                    "user admin from 192.168.1.50"
                ),
                username="admin",
                source_ip="192.168.1.50",
            )
        )

    success_time = (
        start_time
        + timedelta(minutes=5)
    )

    events.append(
        make_event(
            event_id="SUCCESS-1",
            event_type="authentication",
            timestamp=success_time.isoformat(),
            description=(
                "Successful login for user "
                "admin from 192.168.1.50"
            ),
            username="admin",
            source_ip="192.168.1.50",
        )
    )

    alerts = detect_suspicious_activity(
        events
    )

    brute_force_alerts = [
        alert
        for alert in alerts
        if alert["rule_id"]
        == "BRUTE_FORCE_SUCCESS"
    ]

    assert len(
        brute_force_alerts
    ) == 1

    assert (
        brute_force_alerts[0]["severity"]
        == "HIGH"
    )


# ==========================================
# PROCESS CHAIN TEST
# ==========================================

def test_suspicious_process_detection():

    events = [

        make_event(
            event_id="PROCESS-1",
            event_type="process",
            timestamp="2026-09-07T10:07:00",
            description=(
                "Process executed: powershell.exe "
                "(PID 1234, Parent PID 1000)"
            ),
        )

    ]

    alerts = detect_suspicious_activity(
        events
    )

    process_alerts = [
        alert
        for alert in alerts
        if alert["rule_id"]
        == "SUSPICIOUS_PROCESS_CHAIN"
    ]

    assert len(
        process_alerts
    ) == 1

    assert (
        process_alerts[0]["severity"]
        == "HIGH"
    )


# ==========================================
# USB TRANSFER TEST
# ==========================================

def test_usb_transfer_detection():

    events = [

        make_event(
            event_id="USB-1",
            event_type="usb",
            timestamp="2026-09-07T10:15:00",
            description=(
                "USB device connected: "
                "SanDisk USB (USB-001)"
            ),
        ),

        make_event(
            event_id="USB-2",
            event_type="usb",
            timestamp="2026-09-07T10:16:00",
            description=(
                "File copied using USB device "
                "SanDisk USB: "
                "C:\\Users\\admin\\Documents\\"
                "Confidential_Project_Report.pdf"
            ),
        ),

        make_event(
            event_id="USB-3",
            event_type="usb",
            timestamp="2026-09-07T10:20:00",
            description=(
                "USB device disconnected: "
                "SanDisk USB (USB-001)"
            ),
        ),

    ]

    alerts = detect_suspicious_activity(
        events
    )

    usb_alerts = [
        alert
        for alert in alerts
        if alert["rule_id"]
        == "USB_FILE_TRANSFER"
    ]

    assert len(
        usb_alerts
    ) == 1

    assert (
        usb_alerts[0]["severity"]
        == "HIGH"
    )