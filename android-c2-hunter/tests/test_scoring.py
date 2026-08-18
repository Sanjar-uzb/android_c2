from hunter.detection.scoring import score_connection


def test_score_connection_ioc():
    record = {"remote_ip": "8.8.8.8", "remote_port": 4444, "proto": "tcp"}
    score, reasons = score_connection(record, 0, {"8.8.8.8"})
    assert score >= 100
    assert 'IOC_MATCH' in reasons
