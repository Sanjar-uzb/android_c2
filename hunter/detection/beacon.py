import statistics
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List


def analyze_beacon(events: List[Dict[str, Any]], remote_ip: str, remote_port: int) -> Dict[str, Any]:
    """
    Analyze connection events to remote_ip:remote_port for beacon patterns.
    Returns beacon detection metrics and score.
    """
    result = {
        "remote": f"{remote_ip}:{remote_port}",
        "event_count": 0,
        "first_seen": None,
        "last_seen": None,
        "duration_seconds": 0,
        "intervals": [],
        "mean_interval": 0.0,
        "median_interval": 0.0,
        "stddev_interval": 0.0,
        "coefficient_of_variation": 0.0,
        "min_interval": 0.0,
        "max_interval": 0.0,
        "jitter_ratio": 0.0,
        "beacon_score": 0,
        "is_beacon": False,
        "beacon_type": "none",
    }
    
    matching = [e for e in events if e.get("remote_ip") == remote_ip and e.get("remote_port") == remote_port]
    if len(matching) < 2:
        return result
    
    try:
        timestamps = []
        for event in matching:
            ts_str = event.get("timestamp", "")
            if ts_str:
                try:
                    ts = datetime.fromisoformat(ts_str)
                    timestamps.append(ts)
                except (ValueError, TypeError):
                    continue
        
        if len(timestamps) < 2:
            return result
        
        timestamps.sort()
        result["event_count"] = len(timestamps)
        result["first_seen"] = timestamps[0].isoformat()
        result["last_seen"] = timestamps[-1].isoformat()
        result["duration_seconds"] = (timestamps[-1] - timestamps[0]).total_seconds()
        
        # Calculate intervals between consecutive events
        intervals = []
        for i in range(1, len(timestamps)):
            interval = (timestamps[i] - timestamps[i - 1]).total_seconds()
            if interval > 0:
                intervals.append(interval)
        
        if not intervals:
            return result
        
        result["intervals"] = intervals
        result["mean_interval"] = statistics.mean(intervals)
        result["min_interval"] = min(intervals)
        result["max_interval"] = max(intervals)
        
        if len(intervals) >= 2:
            result["median_interval"] = statistics.median(intervals)
            result["stddev_interval"] = statistics.stdev(intervals)
        else:
            result["median_interval"] = intervals[0]
            result["stddev_interval"] = 0
        
        # Coefficient of Variation (jitter metric)
        if result["mean_interval"] > 0:
            result["coefficient_of_variation"] = result["stddev_interval"] / result["mean_interval"]
            result["jitter_ratio"] = min(1.0, result["coefficient_of_variation"])
        
        # Beacon detection logic
        if result["event_count"] >= 5 and result["mean_interval"] > 0:
            # Regular beacon: low jitter + consistent intervals
            if result["coefficient_of_variation"] < 0.15:  # Low variation
                result["beacon_type"] = "regular"
                result["beacon_score"] = 80 + min(20, result["event_count"] * 2)
                result["is_beacon"] = True
            
            # Consistent beacon with some jitter
            elif result["coefficient_of_variation"] < 0.4:
                result["beacon_type"] = "jittered"
                result["beacon_score"] = 60 + min(20, result["event_count"])
                result["is_beacon"] = True
            
            # Periodic with higher variance
            elif result["coefficient_of_variation"] < 0.8 and result["mean_interval"] < 300:
                result["beacon_type"] = "periodic"
                result["beacon_score"] = 40 + result["event_count"] // 2
                result["is_beacon"] = True
        
        elif result["event_count"] >= 10:
            result["beacon_score"] = 30
        
    except Exception:
        pass
    
    return result


def detect_beacons(events: List[Dict[str, Any]], threshold: int = 5) -> List[Dict[str, Any]]:
    """
    Group events by remote endpoint and detect beacon patterns.
    """
    endpoints = defaultdict(list)
    for event in events:
        remote_ip = event.get("remote_ip")
        remote_port = event.get("remote_port", 0)
        if remote_ip and remote_ip not in {"0.0.0.0", "::"}:
            key = (remote_ip, remote_port)
            endpoints[key].append(event)
    
    beacons = []
    for (ip, port), endpoint_events in endpoints.items():
        if len(endpoint_events) >= threshold:
            beacon_analysis = analyze_beacon(events, ip, port)
            if beacon_analysis["is_beacon"]:
                beacons.append(beacon_analysis)
    
    return sorted(beacons, key=lambda x: x["beacon_score"], reverse=True)


def enrich_events_with_beacon_score(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Add beacon detection results to each event.
    """
    beacons = {b["remote"]: b for b in detect_beacons(events, threshold=3)}
    
    enriched = []
    for event in events:
        event_copy = event.copy()
        remote = f"{event.get('remote_ip')}:{event.get('remote_port', 0)}"
        if remote in beacons:
            beacon = beacons[remote]
            event_copy["beacon_analysis"] = {
                "is_beacon": beacon["is_beacon"],
                "beacon_type": beacon["beacon_type"],
                "beacon_score": beacon["beacon_score"],
            }
            event_copy["score"] = event.get("score", 0) + beacon["beacon_score"]
            if "reasons" not in event_copy:
                event_copy["reasons"] = []
            if beacon["is_beacon"]:
                event_copy["reasons"].append(f"BEACON_{beacon['beacon_type'].upper()}")
        enriched.append(event_copy)
    
    return enriched
