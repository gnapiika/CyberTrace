from datetime import timedelta

from core.detection_rules import DETECTION_RULES


# ==========================================
# HELPER FUNCTIONS
# ==========================================

def event_time(event):
    """
    Return the timestamp of an event.
    """

    return event.timestamp


def events_within_window(
    first_event,
    second_event,
    minutes=10,
):
    """
    Check whether two events occurred within
    the specified time window.
    """

    difference = abs(
        event_time(first_event)
        - event_time(second_event)
    )

    return difference <= timedelta(
        minutes=minutes
    )


def create_alert(
    rule_id,
    events,
    explanation=None,
):
    """
    Create a standardized alert dictionary.
    """

    rule = DETECTION_RULES[rule_id]

    timestamps = [
        event.timestamp
        for event in events
    ]

    return {
        "rule_id": rule_id,
        "name": rule["name"],
        "severity": rule["severity"],
        "description": (
            explanation
            if explanation
            else rule["description"]
        ),
        "timestamp": min(timestamps),
        "event_ids": [
            event.event_id
            for event in events
        ],
    }


# ==========================================
# RULE 1
# BRUTE FORCE + SUCCESSFUL LOGIN
# ==========================================

def detect_brute_force(events):
    """
    Detect five or more failed authentication
    attempts followed by a successful login.

    Only one alert is generated for each
    successful login that completes the pattern.
    """

    alerts = []

    authentication_events = [
        event
        for event in events
        if event.event_type == "authentication"
    ]

    authentication_events.sort(
        key=lambda event: event.timestamp
    )

    for index, event in enumerate(
        authentication_events
    ):

        description = (
            event.description or ""
        )

        if "Successful login" not in description:
            continue

        previous_events = (
            authentication_events[:index]
        )

        failed_events = [
            previous
            for previous in previous_events
            if (
                "Failed login" in
                (previous.description or "")
            )
            and previous.username == event.username
            and previous.source_ip == event.source_ip
            and previous.timestamp <= event.timestamp
            and events_within_window(
                previous,
                event,
                minutes=10,
            )
        ]

        if len(failed_events) < 5:
            continue

        related_events = (
            failed_events[-5:]
            + [event]
        )

        alerts.append(
            create_alert(
                rule_id="BRUTE_FORCE_SUCCESS",
                events=related_events,
            )
        )

    return alerts


# ==========================================
# RULE 2
# DOWNLOAD + FILE ACTIVITY + EXECUTION
# ==========================================

def detect_download_execution(events):
    """
    Detect suspicious browser download activity
    followed by related file activity and,
    where available, process execution.

    Only the closest matching sequence is used
    for each download event.
    """

    alerts = []

    browser_events = [
        event
        for event in events
        if event.event_type == "browser"
    ]

    file_events = [
        event
        for event in events
        if event.event_type == "file"
    ]

    process_events = [
        event
        for event in events
        if event.event_type == "process"
    ]

    browser_events.sort(
        key=lambda event: event.timestamp
    )

    file_events.sort(
        key=lambda event: event.timestamp
    )

    process_events.sort(
        key=lambda event: event.timestamp
    )

    for browser_event in browser_events:

        description = (
            browser_event.description or ""
        ).lower()

        if (
            "download" not in description
            and "update" not in description
        ):
            continue

        # ----------------------------------
        # Find the closest file activity
        # after the download.
        # ----------------------------------

        matching_file = None

        for file_event in file_events:

            if file_event.timestamp < (
                browser_event.timestamp
            ):
                continue

            if not events_within_window(
                browser_event,
                file_event,
                minutes=10,
            ):
                continue

            matching_file = file_event
            break

        if matching_file is None:
            continue

        # ----------------------------------
        # Find the closest process execution
        # after the file activity.
        # ----------------------------------

        matching_process = None

        for process_event in process_events:

            if process_event.timestamp < (
                matching_file.timestamp
            ):
                continue

            if not events_within_window(
                matching_file,
                process_event,
                minutes=10,
            ):
                continue

            matching_process = process_event
            break

        # ----------------------------------
        # Prefer the complete sequence.
        # ----------------------------------

        if matching_process is not None:

            related_events = [
                browser_event,
                matching_file,
                matching_process,
            ]

        else:

            related_events = [
                browser_event,
                matching_file,
            ]

        alerts.append(
            create_alert(
                rule_id=(
                    "SUSPICIOUS_DOWNLOAD_EXECUTION"
                ),
                events=related_events,
            )
        )

    return alerts


# ==========================================
# RULE 3
# SUSPICIOUS PROCESS
# ==========================================

def detect_process_chain(events):
    """
    Detect potentially suspicious process
    execution.

    This remains heuristic and does not claim
    that the process is malicious.
    """

    alerts = []

    process_events = [
        event
        for event in events
        if event.event_type == "process"
    ]

    process_events.sort(
        key=lambda event: event.timestamp
    )

    suspicious_process_names = {
        "powershell.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
    }

    for event in process_events:

        description = (
            event.description or ""
        ).lower()

        matched = any(
            process_name in description
            for process_name
            in suspicious_process_names
        )

        if not matched:
            continue

        alerts.append(
            create_alert(
                rule_id="SUSPICIOUS_PROCESS_CHAIN",
                events=[event],
                explanation=(
                    "A potentially suspicious process "
                    "execution was detected. Further "
                    "investigation is required to determine "
                    "whether the activity was legitimate "
                    "or malicious."
                ),
            )
        )

    return alerts


# ==========================================
# RULE 4
# USB FILE TRANSFER
# ==========================================

def detect_usb_transfer(events):
    """
    Detect the sequence:

        USB connect
        ↓
        file copy
        ↓
        USB disconnect

    Only the first complete transfer sequence
    for a connected device is reported.
    """

    alerts = []

    usb_events = [
        event
        for event in events
        if event.event_type == "usb"
    ]

    usb_events.sort(
        key=lambda event: event.timestamp
    )

    for index, connect_event in enumerate(
        usb_events
    ):

        description = (
            connect_event.description or ""
        ).lower()

        if "usb device connected" not in description:
            continue

        # ----------------------------------
        # Search for the first copy event.
        # ----------------------------------

        copy_event = None

        for later in usb_events[index + 1:]:

            later_description = (
                later.description or ""
            ).lower()

            if "file copied" not in later_description:
                continue

            if later.timestamp < (
                connect_event.timestamp
            ):
                continue

            if not events_within_window(
                connect_event,
                later,
                minutes=15,
            ):
                continue

            copy_event = later
            break

        if copy_event is None:
            continue

        # ----------------------------------
        # Find the first disconnect after
        # the copy.
        # ----------------------------------

        disconnect_event = None

        for later in usb_events[index + 1:]:

            later_description = (
                later.description or ""
            ).lower()

            if (
                "usb device disconnected"
                not in later_description
            ):
                continue

            if later.timestamp < (
                copy_event.timestamp
            ):
                continue

            if not events_within_window(
                copy_event,
                later,
                minutes=15,
            ):
                continue

            disconnect_event = later
            break

        if disconnect_event is None:
            continue

        alerts.append(
            create_alert(
                rule_id="USB_FILE_TRANSFER",
                events=[
                    connect_event,
                    copy_event,
                    disconnect_event,
                ],
            )
        )

    return alerts


# ==========================================
# RULE 5
# SUSPICIOUS NETWORK ACTIVITY
# ==========================================

def detect_network_activity(events):
    """
    Detect network activity occurring near
    suspicious process or browser activity.

    One network alert is generated for each
    network event, using the closest suspicious
    event.
    """

    alerts = []

    network_events = [
        event
        for event in events
        if event.event_type == "network"
    ]

    suspicious_events = [
        event
        for event in events
        if event.event_type in {
            "process",
            "browser",
        }
        and (
            "download" in (
                event.description or ""
            ).lower()
            or "powershell" in (
                event.description or ""
            ).lower()
            or "suspicious" in (
                event.description or ""
            ).lower()
        )
    ]

    network_events.sort(
        key=lambda event: event.timestamp
    )

    suspicious_events.sort(
        key=lambda event: event.timestamp
    )

    for network_event in network_events:

        matching_events = [
            suspicious_event
            for suspicious_event in suspicious_events
            if events_within_window(
                network_event,
                suspicious_event,
                minutes=10,
            )
        ]

        if not matching_events:
            continue

        closest_event = min(
            matching_events,
            key=lambda event: abs(
                event.timestamp
                - network_event.timestamp
            ),
        )

        alerts.append(
            create_alert(
                rule_id=(
                    "SUSPICIOUS_NETWORK_ACTIVITY"
                ),
                events=[
                    closest_event,
                    network_event,
                ],
            )
        )

    return alerts


# ==========================================
# RULE 6
# CREATE → EXECUTE → DELETE
# ==========================================

def detect_create_execute_delete(events):
    """
    Detect:

        File create
        ↓
        File execute/access
        ↓
        File delete

    Only the first complete sequence for each
    created file event is reported.
    """

    alerts = []

    file_events = [
        event
        for event in events
        if event.event_type == "file"
    ]

    file_events.sort(
        key=lambda event: event.timestamp
    )

    for index, event in enumerate(
        file_events
    ):

        description = (
            event.description or ""
        ).lower()

        if "file create" not in description:
            continue

        execute_event = None
        delete_event = None

        for later in file_events[index + 1:]:

            later_description = (
                later.description or ""
            ).lower()

            if execute_event is None:

                if (
                    "execute" in later_description
                    or "access" in later_description
                ):

                    if events_within_window(
                        event,
                        later,
                        minutes=15,
                    ):

                        execute_event = later

            elif "delete" in later_description:

                if events_within_window(
                    event,
                    later,
                    minutes=30,
                ):

                    delete_event = later
                    break

        if (
            execute_event is None
            or delete_event is None
        ):
            continue

        alerts.append(
            create_alert(
                rule_id="CREATE_EXECUTE_DELETE",
                events=[
                    event,
                    execute_event,
                    delete_event,
                ],
            )
        )

    return alerts


# ==========================================
# RULE 7
# MULTI-STAGE ACTIVITY
# ==========================================

def detect_multi_stage_activity(
    events,
    existing_alerts,
):
    """
    Detect multiple independent suspicious
    patterns across the investigation.

    A CRITICAL alert is generated only when
    at least two different detection rules
    have fired.
    """

    if len(existing_alerts) < 2:
        return []

    unique_rule_ids = {
        alert["rule_id"]
        for alert in existing_alerts
    }

    if len(unique_rule_ids) < 2:
        return []

    alert_event_ids = set()

    for alert in existing_alerts:

        for event_id in alert["event_ids"]:
            alert_event_ids.add(event_id)

    related_events = [
        event
        for event in events
        if event.event_id in alert_event_ids
    ]

    if not related_events:
        return []

    return [
        create_alert(
            rule_id="MULTI_STAGE_ACTIVITY",
            events=related_events,
            explanation=(
                "Multiple suspicious activity patterns "
                "were correlated across different evidence "
                "sources. This represents a potentially "
                "multi-stage sequence and requires further "
                "investigation."
            ),
        )
    ]


# ==========================================
# RUN ALL DETECTION RULES
# ==========================================

def detect_suspicious_activity(events):
    """
    Run all CyberTrace detection rules.

    Returns a list of unique alert dictionaries.
    """

    alerts = []

    # --------------------------------------
    # Authentication
    # --------------------------------------

    alerts.extend(
        detect_brute_force(events)
    )

    # --------------------------------------
    # Browser / download activity
    # --------------------------------------

    alerts.extend(
        detect_download_execution(events)
    )

    # --------------------------------------
    # Process activity
    # --------------------------------------

    alerts.extend(
        detect_process_chain(events)
    )

    # --------------------------------------
    # USB activity
    # --------------------------------------

    alerts.extend(
        detect_usb_transfer(events)
    )

    # --------------------------------------
    # Network activity
    # --------------------------------------

    alerts.extend(
        detect_network_activity(events)
    )

    # --------------------------------------
    # File lifecycle activity
    # --------------------------------------

    alerts.extend(
        detect_create_execute_delete(events)
    )

    # --------------------------------------
    # Multi-stage correlation
    # --------------------------------------

    multi_stage_alerts = (
        detect_multi_stage_activity(
            events,
            alerts,
        )
    )

    alerts.extend(
        multi_stage_alerts
    )

    # --------------------------------------
    # Final deduplication
    # --------------------------------------

    unique_alerts = []

    seen = set()

    for alert in alerts:

        key = (
            alert["rule_id"],
            tuple(
                sorted(
                    alert["event_ids"]
                )
            ),
        )

        if key in seen:
            continue

        seen.add(key)

        unique_alerts.append(
            alert
        )

    # --------------------------------------
    # Sort alerts chronologically
    # --------------------------------------

    unique_alerts.sort(
        key=lambda alert: alert["timestamp"]
    )

    return unique_alerts