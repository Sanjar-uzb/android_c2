from ipaddress import ip_address

from hunter.detection.ioc import ioc_matches


def score_connection(record: dict, repeat_count: int = 0, iocs: set[str] | None = None):
    iocs = iocs or set()
    ip = record.get("remote_ip")
    port = int(record.get("remote_port", 0) or 0)
    score = 0
    reasons = []

    if ip and ioc_matches(ip, iocs):
        score += 100
        reasons.append("IOC_MATCH")
    if record.get("remote_host") and ioc_matches(record.get("remote_host"), iocs):
        score += 80
        reasons.append("DOMAIN_IOC_MATCH")
    if ip:
        try:
            if not ip_address(ip).is_private:
                score += 5
            else:
                reasons.append("PRIVATE_REMOTE")
        except ValueError:
            pass
    if port in {4444, 5555, 1337, 31337, 12345, 6667, 7001, 8081, 8443, 9001, 9443}:
        score += 20
        reasons.append("SUSPICIOUS_PORT")
    if port > 1024 and port not in {53, 80, 123, 443, 853, 8080, 8443, 5228, 5229, 5230, 9443}:
        score += 8
        reasons.append("UNCOMMON_PORT")
    if repeat_count >= 3:
        score += 8
        reasons.append("REPEATED_CONNECTION")
    if repeat_count >= 10:
        score += 12
        reasons.append("BEACONING")
    if record.get("proto", "").startswith("udp") and port not in {53, 123, 443, 853}:
        score += 10
        reasons.append("NONSTANDARD_UDP")
    if record.get("source") == "frida":
        score += 10
        reasons.append("FRIDA_TRACE")
    return score, reasons


def calculate_risk(records):
    total = 0
    for row in records:
        total += row.get("score", 0)
    return total
