import pandas as pd

from core.event_normalizer import normalize_event


def parse_process_activity(file_path):
    events = []

    dataframe = pd.read_csv(file_path)

    for _, row in dataframe.iterrows():

        timestamp = row.get("timestamp")
        process_name = row.get("process_name", "")
        pid = row.get("pid", "")
        parent_pid = row.get("parent_pid", "")
        username = row.get("username", "")
        executable_path = row.get("executable_path", "")

        if pd.isna(timestamp):
            continue

        if pd.isna(process_name):
            process_name = ""

        if pd.isna(pid):
            pid = ""

        if pd.isna(parent_pid):
            parent_pid = ""

        if pd.isna(username):
            username = None

        if pd.isna(executable_path):
            executable_path = ""

        description = (
            f"Process executed: {process_name} "
            f"(PID {pid}, Parent PID {parent_pid})"
        )

        event = normalize_event(
            event_type="process",
            timestamp=str(timestamp),
            description=description,
            username=username,
            severity="INFO",
            raw_data=row.to_json(),
        )

        event["process_name"] = str(process_name)
        event["pid"] = str(pid)
        event["parent_pid"] = str(parent_pid)
        event["executable_path"] = str(executable_path)

        events.append(event)

    return events