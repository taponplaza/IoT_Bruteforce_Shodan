"""Configuration and constants management for the Shodan IoT/ICS Brute Force Tool."""

from pathlib import Path

# Basic query options (free)
AVAILABLE_QUERIES = {
    "1": "webcam",
    "2": "raspberrypi", 
    "3": "default-passwords",
    "4": "ics",
    "5": "advanced"
}

# Report filename mapping
REPORT_NAMES = {
    "webcam": "webcam_report.html",
    "raspberrypi": "raspberrypi_report.html",
    "default-passwords": "default_password_report.html",
    "ics": "ics_report.html"
}

# Advanced queries for Spain (uses credits)
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

# Result limit options
RESULT_LIMITS = {
    "1": 100,
    "2": 300, 
    "3": 500,
    "4": "custom"
}

# Credit costs for advanced queries
ADVANCED_QUERY_CREDITS = {
    "1": 1,  # ICS systems
    "2": 1,  # Industrial protocols
    "3": 1,  # SSH/Telnet services
    "4": 1,  # IP cameras
    "5": 2,  # Web admin interfaces (more expensive)
    "6": 1   # Network equipment
}

# Specialized wordlists for different device types
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

def create_directories():
    """Create necessary directories for the application."""
    base_dir = Path(__file__).resolve().parents[1]
    (base_dir / "json_data").mkdir(exist_ok=True)
    (base_dir / "reports").mkdir(exist_ok=True)
    (base_dir / "logs").mkdir(exist_ok=True)

def estimate_credits_by_limit(limit):
    """Estimate Shodan credits needed based on result limit."""
    if limit <= 100:
        return 0  # First 100 results are free
    else:
        # Each additional 100 results = +1 credit
        additional_credits = (limit - 100 + 99) // 100  # Round up
        return additional_credits

def calculate_total_cost(query_selection, result_limit):
    """Calculate total cost for a query including base cost and limit cost."""
    base_cost = ADVANCED_QUERY_CREDITS.get(query_selection, 1)
    limit_cost = estimate_credits_by_limit(result_limit)
    total_cost = base_cost + limit_cost
    return total_cost, base_cost, limit_cost