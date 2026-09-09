import pandas as pd

from core.event_normalizer import normalize_event


def parse_usb_activity(file_path):
    events = []

    dataframe = pd.read_csv(file_path)

    for _, row in dataframe.iterrows():

        timestamp = row.get("timestamp")
        action = row.get("action", "")
        device_id = row.get("device_id", "")
        device_name = row.get("device_name", "")
        file_path_value = row.get("file_path", "")
        username = row.get("username", "")

        if pd.isna(timestamp):
            continue

        if pd.isna(action):
            action = ""

        if pd.isna(device_id):
            device_id = ""

        if pd.isna(device_name):
            device_name = ""

        if pd.isna(file_path_value):
            file_path_value = ""

        if pd.isna(username):
            username = None

        action = str(action).upper()

        if action == "CONNECT":
            description = (
                f"USB device connected: "
                f"{device_name} ({device_id})"
            )

        elif action == "DISCONNECT":
            description = (
                f"USB device disconnected: "
                f"{device_name} ({device_id})"
            )

        elif action == "COPY":
            description = (
                f"File copied using USB device "
                f"{device_name}: {file_path_value}"
            )

        else:
            description = (
                f"USB event {action} for "
                f"{device_name} ({device_id})"
            )

        event = normalize_event(
            event_type="usb",
            timestamp=str(timestamp),
            description=description,
            username=username,
            severity="INFO",
            raw_data=row.to_json(),
        )

        event["usb_action"] = action
        event["device_id"] = device_id
        event["device_name"] = device_name
        event["file_path"] = file_path_value

        events.append(event)

    return events