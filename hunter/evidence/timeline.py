from datetime import datetime, timezone


def build_timeline(events):
    items = []
    for event in events:
        ts = event.get("timestamp") or datetime.now(timezone.utc).isoformat()
        items.append({"timestamp": ts, "event": event})
    return sorted(items, key=lambda x: x["timestamp"])
