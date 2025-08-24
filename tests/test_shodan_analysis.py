import sys
from pathlib import Path
import types

sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

import shodan_analysis

class DummyClient:
    def __init__(self, *a, **kw):
        pass
    def search_devices(self, query):
        return []

def test_run_queries_returns_empty(monkeypatch, tmp_path):
    monkeypatch.setattr(shodan_analysis, "ShodanClient", lambda api_key: DummyClient())
    output_file = tmp_path / "out.html"
    results = shodan_analysis.run_queries(["noresult"], output_html=str(output_file))
    assert results == [{"query": "noresult", "count": 0, "devices": []}]
    assert output_file.exists()
