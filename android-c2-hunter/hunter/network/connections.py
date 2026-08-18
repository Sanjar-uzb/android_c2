from collections import defaultdict
from typing import Any, Dict


def summarize_connections(rows):
    summary = defaultdict(lambda: {"events": 0, "score": 0, "ports": set(), "reasons": set()})
    for row in rows:
        key = (row.get("remote_ip"), row.get("remote_port"), row.get("proto"))
        bucket = summary[key]
        bucket["events"] += 1
        bucket["score"] = max(bucket["score"], row.get("score", 0))
        bucket["ports"].add(row.get("remote_port"))
        bucket["reasons"].update(row.get("reasons", []))
    return {k: {**v, "ports": sorted(v["ports"]), "reasons": sorted(v["reasons"])} for k, v in summary.items()}
