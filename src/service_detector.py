"""Service detection for POST forms (FFUF) and authentication services (Hydra)."""

from web_analyzer import WebFormAnalyzer

def detect_service_advanced(target):
    """
    Detect services for FFUF (POST forms) and Hydra (authentication services).
    Returns service type string or None if no compatible service found.
    """
    port = target['port']
    ip = target['ip_str']
    banner = target.get('banner', '').lower()
    product = target.get('product', '').lower()
    
    # STEP 1: Detect web services (HTTP/HTTPS)
    is_web_service = False
    use_https = False
    
    # Standard web ports
    if port in [80, 443, 8080, 8443, 8000, 8888, 9443, 9000, 9090, 8081, 8082, 8008]:
        is_web_service = True
        use_https = port in [443, 8443, 9443]
    
    # Detect web service by banner/product
    elif any(web_indicator in banner for web_indicator in ['http', 'apache', 'nginx', 'iis', 'lighttpd', 'tomcat']):
        is_web_service = True
        use_https = 'https' in banner or 'ssl' in banner
        print(f"      🔍 Web service detected from banner: {banner[:50]}...")
    
    elif any(web_indicator in product for web_indicator in ['apache', 'nginx', 'iis', 'lighttpd', 'tomcat', 'jetty']):
        is_web_service = True
        use_https = 'https' in product or 'ssl' in product
        print(f"      🔍 Web service detected from product: {product[:50]}...")
    
    # If web service, try to detect POST forms
    if is_web_service:
        print(f"      🔍 Analyzing {ip}:{port} for POST forms (FFUF) - {'HTTPS' if use_https else 'HTTP'}")
        
        # Analyze web forms
        web_analyzer = WebFormAnalyzer()
        form_info = web_analyzer.analyze_website(ip, port, use_ssl=use_https)
        
        if form_info and form_info['method'].lower() == 'post':
            # POST form found - use FFUF
            form_path = form_info['action'].replace(form_info['base_url'], '')
            if not form_path:
                form_path = "/"
                
            # Clean path of problematic characters
            if '?' in form_path:
                form_path = form_path.split('?')[0]
                
            # Return FFUF format
            return f"ffuf-post-form:{form_path}:{form_info['username_field']}:{form_info['password_field']}"
        else:
            print(f"      ℹ️  Web service found but no POST forms detected")
    
    # STEP 2: Detect Hydra-compatible services (authentication only)
    print(f"      🔍 Analyzing {ip}:{port} for Hydra services")
    
    # Port to service mapping for Hydra
    hydra_services = {
        21: "ftp",
        22: "ssh", 
        23: "telnet",
        25: "smtp",
        110: "pop3",
        143: "imap",
        993: "imaps",
        995: "pop3s",
        1433: "mssql",
        2222: "ssh",      # Alternative SSH
        2323: "telnet",   # Alternative Telnet
        3306: "mysql",
        3389: "rdp",
        5432: "postgres",
        5900: "vnc",
        6379: "redis",
        27017: "mongodb"
    }
    
    # Detect by known port (but not if already determined to be web)
    if port in hydra_services and not is_web_service:
        service = hydra_services[port]
        print(f"      ✅ Hydra service: {service}")
        return f"hydra:{service}"
    
    # Detect by banner or product information
    if 'ssh' in banner or 'openssh' in product:
        print(f"      ✅ Hydra service: ssh (detected from banner)")
        return "hydra:ssh"
    elif ('ftp' in banner or 'ftp' in product) and not is_web_service:
        print(f"      ✅ Hydra service: ftp (detected from banner)")
        return "hydra:ftp"
    elif 'telnet' in banner or 'telnet' in product:
        print(f"      ✅ Hydra service: telnet (detected from banner)")
        return "hydra:telnet"
    elif 'mysql' in banner or 'mysql' in product:
        print(f"      ✅ Hydra service: mysql (detected from banner)")
        return "hydra:mysql"
    elif 'postgres' in banner or 'postgresql' in product:
        print(f"      ✅ Hydra service: postgres (detected from banner)")
        return "hydra:postgres"
    elif 'vnc' in banner or 'vnc' in product:
        print(f"      ✅ Hydra service: vnc (detected from banner)")
        return "hydra:vnc"
    elif 'redis' in banner or 'redis' in product:
        print(f"      ✅ Hydra service: redis (detected from banner)")
        return "hydra:redis"
    elif 'smtp' in banner or 'postfix' in product or 'sendmail' in product:
        print(f"      ✅ Hydra service: smtp (detected from banner)")
        return "hydra:smtp"
    elif 'imap' in banner or 'dovecot' in product:
        print(f"      ✅ Hydra service: imap (detected from banner)")
        return "hydra:imap"
    elif 'pop3' in banner:
        print(f"      ✅ Hydra service: pop3 (detected from banner)")
        return "hydra:pop3"
    elif 'mongodb' in banner or 'mongo' in product:
        print(f"      ✅ Hydra service: mongodb (detected from banner)")
        return "hydra:mongodb"
    elif 'mssql' in banner or 'microsoft sql' in product:
        print(f"      ✅ Hydra service: mssql (detected from banner)")
        return "hydra:mssql"
    
    # No compatible service found
    print(f"      ❌ No compatible service found for port {port}")
    return None

def get_common_failure_messages():
    """Return common authentication failure messages in multiple languages."""
    return [
        # English
        "Login failed", "Invalid username or password", "Incorrect username or password",
        "Authentication failed", "Access denied", "Invalid login", "Wrong credentials",
        "Bad username or password", "Login error",
        
        # Spanish  
        "Usuario o contraseña incorrectos", "Credenciales incorrectas",
        "Error de autenticación", "Acceso denegado", "Login fallido",
        
        # Common patterns
        "Error", "Failed", "Invalid", "Incorrect"
    ]