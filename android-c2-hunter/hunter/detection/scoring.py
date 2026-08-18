from ipaddress import ip_address


def score_connection(record: dict, repeat_count: int = 0, iocs: set[str] | None = None):
    iocs = iocs or set()
    ip = record.get("remote_ip")
    port = int(record.get("remote_port", 0) or 0)
    score = 0
    reasons = []

    if ip in iocs:
        score += 100
        reasons.append("IOC_MATCH")
    if ip:
        try:
            if not ip_address(ip).is_private:
                score += 1
            else:
                reasons.append("PRIVATE_REMOTE")
        except ValueError:
            pass
    if port in {4444, 5555, 1337, 31337, 12345, 6667}:
        score += 5
        reasons.append("SUSPICIOUS_PORT")
    if port > 1024 and port not in {53, 80, 123, 443, 853, 8080, 8443, 5228, 5229, 5230}:
        score += 2
        reasons.append("UNCOMMON_PORT")
    if repeat_count >= 10:
        score += 2
        reasons.append("REPEATED_CONNECTION")
    if record.get("proto", "").startswith("udp") and port not in {53, 123, 443}:
        score += 1
        reasons.append("NONSTANDARD_UDP")
    return score, reasons


def calculate_risk(records):
    total = 0
    for row in records:
        total += row.get("score", 0)
    return total
