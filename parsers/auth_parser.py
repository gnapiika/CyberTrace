from core.event_normalizer import normalize_event


def parse_auth_log(file_path):
    events = []

    with open(file_path, "r", encoding="utf-8") as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            parts = line.split(",")

            if len(parts) < 4:
                continue

            timestamp = parts[0].strip()
            username = parts[1].strip()
            source_ip = parts[2].strip()
            result = parts[3].strip().upper()

            if result == "FAILURE":
                severity = "LOW"
                description = (
                    f"Failed login attempt for user "
                    f"{username} from {source_ip}"
                )

            elif result == "SUCCESS":
                severity = "INFO"
                description = (
                    f"Successful login for user "
                    f"{username} from {source_ip}"
                )

            else:
                severity = "INFO"
                description = (
                    f"Authentication event for user "
                    f"{username} from {source_ip}"
                )

            event = normalize_event(
                event_type="authentication",
                timestamp=timestamp,
                description=description,
                username=username,
                source_ip=source_ip,
                severity=severity,
                raw_data=line,
            )

            event["authentication_result"] = result

            events.append(event)

    return events