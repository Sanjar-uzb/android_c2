import json
from pathlib import Path


def write_json_report(payload, out_path: str | Path):
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding='utf-8')
    return str(path)
