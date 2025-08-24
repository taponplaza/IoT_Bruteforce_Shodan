"""Client for interacting with the Shodan API."""

import os
import shodan
import yaml


class ShodanClient:
    """Client for interacting with the Shodan API."""
    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.getenv("API_SHODAN", "")
        self.client = shodan.Shodan(self.api_key)  # Store the Shodan client instance

    def search_devices(self, query: str):
        """Search devices using a query and return the matches list."""
        try:
            result = self.client.search(query)
            return result.get("matches", [])
        except Exception as exc:  # pragma: no cover - network related
            return []

    def get_host_info(self, ip: str) -> dict:
        """Get detailed information about a host.

        Args:
            ip: IP address to look up

        Returns:
            Dict containing host information
        """
        try:
            return self.client.host(ip)
        except Exception as e:
            print(f"Error getting host info: {e}")
            return {}


def run_queries(queries: list[str], output_html: str = "report.html"):
    with open(CONFIG_PATH) as f:
        config = yaml.safe_load(f)
    print("Using Shodan API key:", config["shodan_api_key"])
    client = ShodanClient(api_key=config["shodan_api_key"])
    results = []
    for q in queries:
        matches = client.search_devices(q)
        print(f"Consulta: {q} - Resultados: {len(matches)}")
        if matches:
            print("Primer resultado:", matches[0])  # Muestra el primer resultado para inspección
        else:
            print("No se encontraron resultados para esta consulta.")
        # Recoge detalles para el reporte
        detailed_matches = []
        for m in matches:
            opts = m.get("opts", {})
            screenshot_url = None
            if "screenshot" in opts:
                screenshot_url = opts["screenshot"].get("url")
            detailed_matches.append({
                "ip_str": m.get("ip_str"),
                "port": m.get("port"),
                "org": m.get("org"),
                "hostnames": m.get("hostnames"),
                "location": m.get("location", {}).get("country_name"),
                "data": m.get("data"),
                "screenshot_url": screenshot_url,
            })
        results.append({"query": q, "count": len(matches), "devices": detailed_matches})

    print("Resultados completos:", results)  # Muestra todos los resultados antes de renderizar
    html = generate_report(results, TEMPLATE)
    Path(output_html).write_text(html)
    return results
