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
    Detect multiple failed authentication attempts
    followed by a successful login.

    Current rule:
    5 or more failures followed by success.
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

        # Only successful logins can complete
        # this detection pattern.
        if "Successful login" not in (
            event.description or ""
        ):
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
            and events_within_window(
                previous,
                event,
                minutes=10,
            )
        ]

        if len(failed_events) >= 5:

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
# DOWNLOAD + FILE ACTIVITY
# ==========================================

def detect_download_execution(events):
    """
    Detect browser download activity followed by
    suspicious file/process activity.
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

    for browser_event in browser_events:

        description = (
            browser_event.description or ""
        ).lower()

        if (
            "download" not in description
            and "update" not in description
        ):
            continue

        # Look for file activity after download
        for file_event in file_events:

            if (
                file_event.timestamp
                < browser_event.timestamp
            ):
                continue

            if not events_within_window(
                browser_event,
                file_event,
                minutes=10,
            ):
                continue

            # Look for process execution after
            # the downloaded file activity.
            for process_event in process_events:

                if (
                    process_event.timestamp
                    < file_event.timestamp
                ):
                    continue

                if not events_within_window(
                    file_event,
                    process_event,
                    minutes=10,
                ):
                    continue

                related_events = [
                    browser_event,
                    file_event,
                    process_event,
                ]

                alerts.append(
                    create_alert(
                        rule_id=(
                            "SUSPICIOUS_DOWNLOAD_EXECUTION"
                        ),
                        events=related_events,
                    )
                )

                break

            else:

                # Download followed by file creation
                # is still useful evidence.
                related_events = [
                    browser_event,
                    file_event,
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
# SUSPICIOUS PROCESS CHAIN
# ==========================================

def detect_process_chain(events):
    """
    Detect potentially suspicious process chains.

    This is intentionally heuristic.
    It does NOT claim that a process is malicious.
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

        related_events = [
            event
        ]

        alerts.append(
            create_alert(
                rule_id="SUSPICIOUS_PROCESS_CHAIN",
                events=related_events,
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
    Detect:

        USB connect
        ↓
        file activity
        ↓
        USB disconnect
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

    for index, event in enumerate(
        usb_events
    ):

        description = (
            event.description or ""
        ).lower()

        if "usb device connected" not in description:
            continue

        device_id = getattr(
            event,
            "raw_data",
            ""
        )

        later_events = usb_events[
            index + 1:
        ]

        copy_events = [
            later
            for later in later_events
            if "file copied" in (
                later.description or ""
            ).lower()
            and events_within_window(
                event,
                later,
                minutes=15,
            )
        ]

        if not copy_events:
            continue

        for copy_event in copy_events:

            disconnect_events = [
                later
                for later in later_events
                if (
                    "usb device disconnected"
                    in (
                        later.description
                        or ""
                    ).lower()
                )
                and later.timestamp
                >= copy_event.timestamp
                and events_within_window(
                    copy_event,
                    later,
                    minutes=15,
                )
            ]

            if disconnect_events:

                related_events = [
                    event,
                    copy_event,
                    disconnect_events[0],
                ]

                alerts.append(
                    create_alert(
                        rule_id="USB_FILE_TRANSFER",
                        events=related_events,
                    )
                )

                break

    return alerts


# ==========================================
# RULE 5
# SUSPICIOUS NETWORK ACTIVITY
# ==========================================

def detect_network_activity(events):
    """
    Detect network activity occurring near
    suspicious process or download activity.
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

    for network_event in network_events:

        for suspicious_event in suspicious_events:

            if events_within_window(
                network_event,
                suspicious_event,
                minutes=10,
            ):

                alerts.append(
                    create_alert(
                        rule_id=(
                            "SUSPICIOUS_NETWORK_ACTIVITY"
                        ),
                        events=[
                            suspicious_event,
                            network_event,
                        ],
                    )
                )

                break

    return alerts


# ==========================================
# RULE 6
# CREATE → EXECUTE → DELETE
# ==========================================

def detect_create_execute_delete(events):
    """
    Detect a file that is created, executed/accessed,
    and later deleted.
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

        remaining_events = file_events[
            index + 1:
        ]

        execute_event = None
        delete_event = None

        for later in remaining_events:

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

            elif (
                "delete" in later_description
            ):

                if events_within_window(
                    event,
                    later,
                    minutes=30,
                ):

                    delete_event = later

                    break

        if (
            execute_event is not None
            and delete_event is not None
        ):

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
    Detect multiple suspicious stages within
    the same investigation.

    This produces a CRITICAL alert only when
    multiple independent suspicious patterns
    have already been detected.
    """

    if len(existing_alerts) < 2:

        return []

    alert_event_ids = set()

    for alert in existing_alerts:

        for event_id in alert["event_ids"]:

            alert_event_ids.add(
                event_id
            )

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

    Returns a list of alert dictionaries.
    """

    alerts = []

    alerts.extend(
        detect_brute_force(events)
    )

    alerts.extend(
        detect_download_execution(events)
    )

    alerts.extend(
        detect_process_chain(events)
    )

    alerts.extend(
        detect_usb_transfer(events)
    )

    alerts.extend(
        detect_network_activity(events)
    )

    alerts.extend(
        detect_create_execute_delete(events)
    )

    multi_stage_alerts = (
        detect_multi_stage_activity(
            events,
            alerts,
        )
    )

    alerts.extend(
        multi_stage_alerts
    )

    # Remove duplicate alerts
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

    return unique_alerts