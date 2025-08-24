"""Configuration and constants management."""

from pathlib import Path

# EXACTAMENTE como en original_main.py
AVAILABLE_QUERIES = {
    "1": "webcam",
    "2": "raspberrypi", 
    "3": "default-passwords",
    "4": "ics",
    "5": "advanced"  # Nueva opción
}

# Mapping for report names - EXACTO del original
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

# NUEVO: Sistema de wordlists personalizados - EXACTO del original
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
    """Create necessary directories - EXACTO del original."""
    base_dir = Path(__file__).resolve().parents[1]
    (base_dir / "json_data").mkdir(exist_ok=True)
    (base_dir / "reports").mkdir(exist_ok=True)

def estimate_credits_by_limit(limit):
    """Estimate Shodan credits based on result limit - EXACTO del original."""
    if limit <= 100:
        return 0  # Primeros 100 resultados gratis
    else:
        # Cada 100 resultados adicionales = +1 crédito
        additional_credits = (limit - 100 + 99) // 100  # Redondeo hacia arriba
        return additional_credits

def calculate_total_cost(query_selection, result_limit):
    """Calculate total cost for a query including base cost and limit cost - EXACTO del original."""
    base_cost = ADVANCED_QUERY_CREDITS.get(query_selection, 1)
    limit_cost = estimate_credits_by_limit(result_limit)
    total_cost = base_cost + limit_cost
    return total_cost, base_cost, limit_cost