import json
from pathlib import Path
from typing import Iterable, Any


def collect_events(records: Iterable[dict], out_path: str | Path):
    out_path = Path(out_path)
    out_path.mkdir(parents=True, exist_ok=True)
    file_path = out_path / "events.jsonl"
    with file_path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    return str(file_path)
