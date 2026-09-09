import pandas as pd

from core.event_normalizer import normalize_event


def parse_file_activity(file_path):
    events = []

    dataframe = pd.read_csv(file_path)

    for _, row in dataframe.iterrows():

        timestamp = row.get("timestamp")
        action = row.get("action", "")
        path = row.get("path", "")
        username = row.get("username", "")

        if pd.isna(timestamp):
            continue

        if pd.isna(action):
            action = ""

        if pd.isna(path):
            path = ""

        if pd.isna(username):
            username = None

        action = str(action).upper()

        description = (
            f"File {action.lower()}: {path}"
        )

        event = normalize_event(
            event_type="file",
            timestamp=str(timestamp),
            description=description,
            username=username,
            severity="INFO",
            raw_data=row.to_json(),
        )

        event["file_action"] = action
        event["file_path"] = path

        events.append(event)

    return events