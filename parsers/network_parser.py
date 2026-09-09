import pandas as pd

from core.event_normalizer import normalize_event


def parse_network_activity(file_path):
    events = []

    dataframe = pd.read_csv(file_path)

    for _, row in dataframe.iterrows():

        timestamp = row.get("timestamp")
        source_ip = row.get("source_ip", "")
        destination_ip = row.get("destination_ip", "")
        port = row.get("port", "")
        protocol = row.get("protocol", "")
        process = row.get("process", "")

        if pd.isna(timestamp):
            continue

        if pd.isna(source_ip):
            source_ip = ""

        if pd.isna(destination_ip):
            destination_ip = ""

        if pd.isna(port):
            port = ""

        if pd.isna(protocol):
            protocol = ""

        if pd.isna(process):
            process = ""

        description = (
            f"Network connection from {source_ip} "
            f"to {destination_ip}:{port} "
            f"using {protocol}"
        )

        if process:
            description += f" by {process}"

        event = normalize_event(
            event_type="network",
            timestamp=str(timestamp),
            description=description,
            source_ip=str(source_ip),
            destination_ip=str(destination_ip),
            severity="INFO",
            raw_data=row.to_json(),
        )

        event["port"] = str(port)
        event["protocol"] = str(protocol)
        event["process"] = str(process)

        events.append(event)

    return events