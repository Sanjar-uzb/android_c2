from pathlib import Path

from hunter.reporting.html import write_html_report


def test_html_report_contains_summary_section(tmp_path):
    out = tmp_path / 'report.html'
    payload = {
        'summary': {'total_events': 3, 'ioc_matches': 1, 'max_score': 150},
        'rows': [{'remote': '8.8.8.8:443', 'score': 150, 'ioc': True}],
    }

    write_html_report(payload, str(out))

    content = out.read_text(encoding='utf-8')
    assert 'Android C2 Hunter Report' in content
    assert 'IOC Matches' in content
    assert '8.8.8.8:443' in content
