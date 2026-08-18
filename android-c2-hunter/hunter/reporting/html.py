import json
from pathlib import Path


def write_html_report(summary, out_path: str):
    summary_payload = summary or {}
    rows = summary_payload.get('rows', [])
    summary_data = summary_payload.get('summary', {})

    table_rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            row.get('remote_ip', row.get('remote', '')),
            row.get('proto', 'tcp'),
            row.get('score', 0),
            'yes' if row.get('ioc') else 'no',
            ', '.join(row.get('reasons', []))
        )
        for row in rows
    )

    html = f"""
    <html>
      <head>
        <meta charset="utf-8" />
        <title>Android C2 Hunter Report</title>
        <style>
          body {{ font-family: Arial, sans-serif; margin: 24px; }}
          table {{ border-collapse: collapse; width: 100%; margin-top: 16px; }}
          th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
          th {{ background: #f3f3f3; }}
          .meta {{ margin-bottom: 12px; }}
        </style>
      </head>
      <body>
        <h1>Android C2 Hunter Report</h1>
        <div class="meta">
          <strong>Total events:</strong> {summary_data.get('total_events', 0)}<br>
          <strong>IOC Matches:</strong> {summary_data.get('ioc_matches', 0)}<br>
          <strong>Max score:</strong> {summary_data.get('max_score', 0)}
        </div>
        <table>
          <thead>
            <tr>
              <th>Remote</th>
              <th>Proto</th>
              <th>Score</th>
              <th>IOC</th>
              <th>Reasons</th>
            </tr>
          </thead>
          <tbody>
            {table_rows or '<tr><td colspan="5">No events captured</td></tr>'}
          </tbody>
        </table>
      </body>
    </html>
    """
    target = Path(out_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(html, encoding='utf-8')
    return str(target)
