import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))
from report import generate_report


def test_generate_report(tmp_path):
    template = tmp_path / "template.html"
    template.write_text("<p>{{ results|length }}</p>")
    html = generate_report([{"query": "q", "count": 1}], template)
    assert "<p>1</p>" in html


def test_generate_report_escapes_html(tmp_path):
    template = tmp_path / "template.html"
    template.write_text("<pre>{{ results[0].html }}</pre>")
    html = generate_report([{"html": "<b>bold</b>"}], template)
    assert "&lt;b&gt;bold&lt;/b&gt;" in html
