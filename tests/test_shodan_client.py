import sys
from pathlib import Path
import types

# Add src directory to sys.path for imports
sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

import shodan_client
from shodan_client import ShodanClient


def test_search_devices_returns_matches(monkeypatch):
    class DummyShodan:
        def __init__(self, api_key):
            self.api_key = api_key
        def search(self, query):
            return {"matches": [{"ip_str": "1.1.1.1"}]}

    monkeypatch.setattr(shodan_client, "shodan", types.SimpleNamespace(Shodan=DummyShodan))
    client = ShodanClient(api_key="dummy")
    results = client.search_devices("test")
    assert results == [{"ip_str": "1.1.1.1"}]
