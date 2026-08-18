def build_summary(records):
    summary = {
        "total_events": len(records),
        "max_score": max((r.get("score", 0) for r in records), default=0),
        "ioc_matches": sum(1 for r in records if r.get("ioc") is True),
    }
    return summary
