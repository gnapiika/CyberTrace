import pandas as pd

from core.event_normalizer import normalize_event


def parse_browser_history(file_path):
    events = []

    dataframe = pd.read_csv(file_path)

    for _, row in dataframe.iterrows():

        timestamp = row.get("timestamp")
        url = row.get("url", "")
        title = row.get("title", "")

        if pd.isna(timestamp):
            continue

        if pd.isna(url):
            url = ""

        if pd.isna(title):
            title = ""

        description = f"Visited {title} ({url})"

        event = normalize_event(
            event_type="browser",
            timestamp=str(timestamp),
            description=description,
            severity="INFO",
            raw_data=row.to_json(),
        )

        events.append(event)

    return events