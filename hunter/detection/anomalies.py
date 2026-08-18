def detect_anomalies(records):
    anomalies = []
    for record in records:
        if record.get("score", 0) >= 100:
            anomalies.append({"type": "ioc_match", "record": record})
    return anomalies
