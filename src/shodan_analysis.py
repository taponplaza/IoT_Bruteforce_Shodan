"""Run a set of Shodan queries and generate a simple report."""

import time
import yaml
import shodan
from pathlib import Path
from shodan_client import ShodanClient
from report import generate_report

TEMPLATE = Path(__file__).resolve().parents[1] / "templates" / "report.html.j2"
CONFIG_PATH = Path(__file__).resolve().parents[1] / "config" / "config.yaml"


def run_basic_search(query: str, output_html: str, api_key: str, limit: int = None):
    """Run a basic Shodan search and generate HTML report.
    
    Args:
        query: Single query to run
        output_html: Path to output HTML report
        api_key: Shodan API key
        limit: Maximum number of results to return
        
    Returns:
        tuple: (results dict, targets list)
    """
    api = shodan.Shodan(api_key)
    targets = []
    detailed_matches = []
    
    try:
        # Use search_cursor for efficient iteration with limit
        counter = 0
        total_available = 0
        
        # First get total count for reporting
        try:
            search_result = api.search(query, limit=1)
            total_available = search_result.get('total', 0)
        except:
            total_available = 0
        
        print(f"🔍 Starting search for: {query}")
        if limit:
            print(f"📊 Limiting to {limit} results (total available: {total_available})")
        else:
            print(f"📊 Getting all available results (total: {total_available})")
        
        # Use search_cursor for efficient iteration
        for banner in api.search_cursor(query):
            # Extract information from banner
            ip = banner.get("ip_str")
            port = banner.get("port")
            
            if ip:
                # Add target information for brute force with extended data
                targets.append({
                    'ip_str': ip,
                    'port': port,
                    'product': banner.get('product', 'Unknown'),
                    'version': banner.get('version', ''),
                    'org': banner.get('org', ''),
                    'isp': banner.get('isp', ''),
                    'asn': banner.get('asn', ''),
                    'location': banner.get('location', {}),
                    'country_name': banner.get('location', {}).get('country_name', ''),
                    'city': banner.get('location', {}).get('city', ''),
                    'timestamp': banner.get('timestamp', ''),
                    'banner': banner.get('data', ''),
                    'hostnames': banner.get('hostnames', []),
                    'domains': banner.get('domains', []),
                    'transport': banner.get('transport', ''),
                    'ssl': banner.get('ssl', {}),
                    'http': banner.get('http', {}),
                    'os': banner.get('os', ''),
                    'device_type': banner.get('devicetype', ''),
                    'cpe': banner.get('cpe', []),
                    'tags': banner.get('tags', []),
                    'vulns': banner.get('vulns', {}),  # Dict format as per Shodan API
                    'title': banner.get('http', {}).get('title', '') if banner.get('http') else '',
                    'server': banner.get('http', {}).get('server', '') if banner.get('http') else ''
                })
                
                # Add detailed match for report with extended information
                detailed_matches.append({
                    "ip_str": ip,
                    "port": port,
                    "org": banner.get("org"),
                    "isp": banner.get("isp"),
                    "asn": banner.get("asn"),
                    "hostnames": banner.get("hostnames", []),
                    "domains": banner.get("domains", []),
                    "location": banner.get("location"),
                    "country_name": banner.get('location', {}).get('country_name', ''),
                    "city": banner.get('location', {}).get('city', ''),
                    "data": banner.get("data"),
                    "product": banner.get("product"),
                    "version": banner.get("version"),
                    "transport": banner.get("transport"),
                    "os": banner.get("os"),
                    "device_type": banner.get("devicetype"),
                    "tags": banner.get("tags", []),
                    "vulns": banner.get("vulns", {}),  # Dict format as per Shodan API
                    "ssl": banner.get("ssl"),
                    "http": banner.get("http"),
                    "title": banner.get('http', {}).get('title', '') if banner.get('http') else '',
                    "server": banner.get('http', {}).get('server', '') if banner.get('http') else '',
                    "timestamp": banner.get("timestamp"),
                    "cpe": banner.get("cpe", [])
                })
            
            # Increment counter and check limit
            counter += 1
            
            # Show progress every 50 results
            if counter % 50 == 0:
                print(f"📥 Downloaded {counter} results...")
            
            # Break if we've reached the limit
            if limit and counter >= limit:
                print(f"🛑 Reached limit of {limit} results")
                break
        
        print(f"✅ Search completed: {counter} devices found")
        
        # Create results structure for report generation
        results = [{
            "query": query,
            "count": counter,
            "total_results": total_available,
            "limit_applied": limit if limit else "None",
            "devices": detailed_matches
        }]
        
        # Generate HTML report
        html = generate_report(results, TEMPLATE)
        Path(output_html).write_text(html)
        
        print(f"📄 Report generated: {output_html}")
        if limit and counter >= limit:
            print(f"🔢 Results limited to {limit} (total available: {total_available})")
        
        return results, targets
        
    except shodan.APIError as e:
        print(f"Shodan API Error: {e}")
        return None, None
    except Exception as e:
        print(f"Error in Shodan search: {e}")
        return None, None


def get_api_info(api_key: str) -> dict:
    """Get Shodan API information including available credits.
    
    Args:
        api_key: Shodan API key
        
    Returns:
        Dict containing API information
    """
    try:
        api = shodan.Shodan(api_key)
        info = api.info()
        return {
            'credits_remaining': info['query_credits'],
            'scan_credits': info.get('scan_credits', 0),
            'plan': info.get('plan', 'unknown')
        }
    except Exception as e:
        print(f"Error getting API info: {e}")
        return {'credits_remaining': 0, 'scan_credits': 0, 'plan': 'unknown'}


# Keep the old function for backward compatibility but simplified
def run_queries(queries: list[str], output_html: str = "report.html", advanced: bool = False):
    """Run Shodan queries and generate reports.
    
    Args:
        queries: List of queries to run
        output_html: Path to output HTML report
        advanced: Whether to perform advanced host lookups (ignored now)
        
    Returns:
        tuple: (results list, targets list)
    """
    with open(CONFIG_PATH) as f:
        config = yaml.safe_load(f)
    
    # Use the first query for simplicity
    if queries:
        return run_basic_search(queries[0], output_html, config["shodan_api_key"])
    return [], []


if __name__ == "__main__":  # pragma: no cover - manual execution
    sample_queries = ["webcam", "raspberrypi", "default password"]
    run_queries(sample_queries)
