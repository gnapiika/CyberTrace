from datetime import timedelta


CORRELATION_WINDOW_MINUTES = 10


def events_within_window(event_a, event_b, minutes=CORRELATION_WINDOW_MINUTES):
    difference = abs(event_a.timestamp - event_b.timestamp)
    return difference <= timedelta(minutes=minutes)


def correlate_events(events):
    """
    Find relationships between events from different evidence sources.
    Returns a list of correlated event groups.
    """

    sorted_events = sorted(events, key=lambda event: event.timestamp)

    correlations = []

    for index, event in enumerate(sorted_events):
        related_events = [event]
        evidence_types = {event.event_type}

        for other_event in sorted_events[index + 1:]:
            if other_event.timestamp < event.timestamp:
                continue

            if not events_within_window(event, other_event):
                if other_event.timestamp > event.timestamp + timedelta(
                    minutes=CORRELATION_WINDOW_MINUTES
                ):
                    break
                continue

            if other_event.event_type == event.event_type:
                continue

            if (
                event.username
                and other_event.username
                and event.username == other_event.username
            ):
                related_events.append(other_event)
                evidence_types.add(other_event.event_type)

            elif (
                event.source_ip
                and other_event.source_ip
                and event.source_ip == other_event.source_ip
            ):
                related_events.append(other_event)
                evidence_types.add(other_event.event_type)

            elif (
                event.destination_ip
                and other_event.destination_ip
                and event.destination_ip == other_event.destination_ip
            ):
                related_events.append(other_event)
                evidence_types.add(other_event.event_type)

            elif (
                event.event_type in {"browser", "file"}
                and other_event.event_type in {"file", "process"}
            ):
                related_events.append(other_event)
                evidence_types.add(other_event.event_type)

            elif (
                event.event_type == "process"
                and other_event.event_type == "network"
            ):
                related_events.append(other_event)
                evidence_types.add(other_event.event_type)

            elif (
                event.event_type == "usb"
                and other_event.event_type == "file"
            ):
                related_events.append(other_event)
                evidence_types.add(other_event.event_type)

            elif (
                event.event_type == "file"
                and other_event.event_type == "usb"
            ):
                related_events.append(other_event)
                evidence_types.add(other_event.event_type)

        if len(related_events) >= 2 and len(evidence_types) >= 2:
            correlations.append(
                {
                    "events": related_events,
                    "evidence_types": sorted(evidence_types),
                    "start_time": related_events[0].timestamp,
                    "end_time": related_events[-1].timestamp,
                }
            )

    return merge_correlations(correlations)


def merge_correlations(correlations):
    """
    Merge correlation groups that share events.
    """

    merged = []

    for correlation in correlations:
        current_event_ids = {
            event.event_id for event in correlation["events"]
        }

        merged_into_existing = False

        for existing in merged:
            existing_event_ids = {
                event.event_id for event in existing["events"]
            }

            if current_event_ids.intersection(existing_event_ids):
                combined_events = existing["events"] + correlation["events"]

                unique_events = {}
                for event in combined_events:
                    unique_events[event.event_id] = event

                existing["events"] = sorted(
                    unique_events.values(),
                    key=lambda event: event.timestamp,
                )

                existing["evidence_types"] = sorted(
                    {
                        event.event_type
                        for event in existing["events"]
                    }
                )

                existing["start_time"] = min(
                    event.timestamp for event in existing["events"]
                )

                existing["end_time"] = max(
                    event.timestamp for event in existing["events"]
                )

                merged_into_existing = True
                break

        if not merged_into_existing:
            merged.append(correlation)

    return merged


def build_correlation_summary(correlation):
    events = correlation["events"]

    event_descriptions = [
        event.description
        for event in events
        if event.description
    ]

    return {
        "start_time": correlation["start_time"],
        "end_time": correlation["end_time"],
        "event_count": len(events),
        "evidence_types": correlation["evidence_types"],
        "events": event_descriptions,
    }