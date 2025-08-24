"""Module to perform brute force against web forms using FFUF and services using Hydra."""

# Asegurar que estos imports estén al principio del archivo

import subprocess
import tempfile
import os
import json
import itertools
import time  # Agregar este import si no está


def create_wordlist_files(username_list, password_list):
    """Create temporary files for username and password lists."""
    # Create temporary username file
    username_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
    for username in username_list:
        username_file.write(username + '\n')
    username_file.close()
    
    # Create temporary password file
    password_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
    for password in password_list:
        password_file.write(password + '\n')
    password_file.close()
    
    return username_file.name, password_file.name


def get_login_page_size(target_url):
    """Get the size of the main login page (NOT a failure test)."""
    try:
        import requests
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
        
        # GET the main login page
        response = requests.get(
            target_url,
            headers=headers,
            timeout=10,
            verify=False,
            allow_redirects=True
        )
        
        login_page_size = len(response.content)
        print(f"      📏 Login page size: {login_page_size} bytes")
        
        return login_page_size
        
    except Exception as e:
        print(f"      ⚠️  Error getting login page size: {str(e)[:50]}")
        return None


def attack_web_form(target_ip, target_port, form_info, username_list, password_list):
    """Attack web form using FFUF - size-based detection only."""
    
    try:
        is_https = form_info['action'].startswith('https')
        protocol = "https" if is_https else "http"
        
        # Extraer path limpio
        form_path = form_info['action'].replace(form_info['base_url'], '')
        if not form_path:
            form_path = "/"
        
        # Limpiar caracteres problemáticos
        if '?' in form_path:
            original_path = form_path
            form_path = form_path.split('?')[0]
            print(f"      ⚠️  Simplified path: {original_path} → {form_path}")
            
        # Parámetros del formulario
        username_field = form_info['username_field']
        password_field = form_info['password_field']
        
        # URL completa
        target_url = f"{protocol}://{target_ip}:{target_port}{form_path}"
        
        print(f"      🔧 Fields: {username_field} / {password_field}")
        print(f"      📝 Testing {len(username_list)} × {len(password_list)} = {len(username_list) * len(password_list)} combinations")
        
        # PASO 1: Obtener tamaño de la página principal de login
        print(f"      🔍 Getting login page size...")
        login_page_size = get_login_page_size(target_url)
        
        if not login_page_size:
            print(f"      ❌ Could not get login page size")
            return False
        
        # Calcular tamaño mínimo para considerar éxito
        # Una página exitosa debe ser significativamente más grande
        success_threshold = login_page_size + 500  # Al menos 500 bytes más grande
        
        print(f"      📏 Success threshold: >{success_threshold} bytes (login page + 500)")
        
        # PASO 2: Crear wordlist combinada para FFUF
        combined_wordlist = create_combined_wordlist(username_list, password_list)
        
        # PASO 3: Crear archivo temporal para resultados JSON
        output_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        output_file.close()
        
        # COMANDO FFUF - Filtrar por tamaño mínimo
        command = [
            "ffuf",
            "-u", target_url,
            "-w", combined_wordlist,
            "-X", "POST",
            "-d", f"{username_field}=FUZZUSER&{password_field}=FUZZPASS",
            "-H", "Content-Type: application/x-www-form-urlencoded",
            "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "-fs", f"{login_page_size}",  # Filter responses with same size as login page
            "-o", output_file.name,
            "-of", "json",
            "-t", "1",  # Single thread
            "-p", "1.0",  # 1 second delay
            "-timeout", "10",
            "-s",  # Silent mode
            "-k",  # Ignore SSL errors
            "-r"   # Follow redirects
        ]
        
        # Verificar si FFUF está disponible
        try:
            test_result = subprocess.run(["ffuf", "-h"], capture_output=True, text=True, timeout=5)
            if test_result.returncode != 0:
                print(f"      ❌ FFUF not working properly")
                return False
        except FileNotFoundError:
            print(f"      ❌ FFUF not found in PATH")
            return False
        
        # Mostrar comando COMPLETO
        cmd_display = " ".join(command)
        print(f"      💻 FFUF Command: {cmd_display}")
        print(f"      📏 Looking for responses > {success_threshold} bytes")
        
        # Ejecutar FFUF
        print(f"      🚀 Running FFUF attack...")
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        
        # Debug mínimo
        if result.returncode != 0 and result.stderr:
            print(f"      ⚠️  FFUF error: {result.stderr[:100]}")
        
        # Analizar resultados con el nuevo threshold
        success = analyze_ffuf_results_by_size(output_file.name, login_page_size, success_threshold)
        
        return success
            
    except subprocess.TimeoutExpired:
        print(f"      ⏰ FFUF attack timed out")
        return False
    except Exception as e:
        print(f"      ❌ Unexpected error: {str(e)[:50]}")
        return False
    finally:
        # Cleanup
        try:
            if 'combined_wordlist' in locals():
                os.unlink(combined_wordlist)
            if 'output_file' in locals():
                os.unlink(output_file.name)
        except:
            pass


def create_combined_wordlist(username_list, password_list):
    """Create simple wordlist with username:password format for FFUF."""
    combined_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
    
    # Generate all combinations in simple format
    for username in username_list:
        for password in password_list:
            # Simple format for FFUF: username:password
            combined_file.write(f"{username}:{password}\n")
    
    combined_file.close()
    return combined_file.name


def analyze_ffuf_results_by_size(output_file, login_page_size, success_threshold):
    """Analyze FFUF results based on page size only."""
    try:
        if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
            print(f"      ℹ️  No different responses found")
            return False
        
        with open(output_file, 'r') as f:
            content = f.read().strip()
            
        if not content:
            print(f"      ℹ️  FFUF found no different responses")
            return False
            
        try:
            results = json.loads(content)
        except json.JSONDecodeError:
            print(f"      ⚠️  Invalid FFUF output format")
            return False
        
        if 'results' not in results or not results['results']:
            print(f"      ℹ️  All responses had same size as login page")
            return False
        
        print(f"      🔍 Found {len(results['results'])} different responses")
        
        valid_credentials = []
        
        # Analizar por tamaño únicamente
        for result in results['results'][:10]:  # Mostrar máximo 10
            status = result.get('status', 0)
            length = result.get('length', 0)
            input_data = result.get('input', {})
            
            # Extraer credenciales
            credentials = "unknown:unknown"
            if input_data:
                for key, value in input_data.items():
                    if ':' in str(value):
                        credentials = str(value)
                        break
            
            # CRITERIO ÚNICO: Tamaño de respuesta
            if length >= success_threshold:
                print(f"      🎉 SUCCESS: {credentials} - Response size: {length} bytes (>{success_threshold})")
                valid_credentials.append(credentials)
            elif length > login_page_size:
                print(f"      🔍 POTENTIAL: {credentials} - Response size: {length} bytes (larger but < threshold)")
                valid_credentials.append(credentials)
            else:
                print(f"      ❌ Too small: {credentials} - Response size: {length} bytes")
        
        # Resumen
        if valid_credentials:
            print(f"      ✅ Found {len(valid_credentials)} valid/potential credential(s)")
            return True
        else:
            print(f"      ❌ No significantly larger responses found")
            return False
        
    except Exception as e:
        print(f"      ⚠️  Error analyzing results: {str(e)[:50]}")
        return False


# Agregar nueva función que retorna las credenciales encontradas

def attack_web_form_with_results(target_ip, target_port, form_info, username_list, password_list):
    """Attack web form using FFUF - returns success status and found credentials."""
    
    try:
        is_https = form_info['action'].startswith('https')
        protocol = "https" if is_https else "http"
        
        # Extraer path limpio
        form_path = form_info['action'].replace(form_info['base_url'], '')
        if not form_path:
            form_path = "/"
        
        # Limpiar caracteres problemáticos
        if '?' in form_path:
            original_path = form_path
            form_path = form_path.split('?')[0]
            print(f"      ⚠️  Simplified path: {original_path} → {form_path}")
            
        # Parámetros del formulario
        username_field = form_info['username_field']
        password_field = form_info['password_field']
        
        # URL completa
        target_url = f"{protocol}://{target_ip}:{target_port}{form_path}"
        
        print(f"      🔧 Fields: {username_field} / {password_field}")
        print(f"      📝 Testing {len(username_list)} × {len(password_list)} = {len(username_list) * len(password_list)} combinations")
        
        # PASO 1: Obtener tamaño de la página principal de login
        print(f"      🔍 Getting login page size...")
        login_page_size = get_login_page_size(target_url)
        
        if not login_page_size:
            print(f"      ❌ Could not get login page size")
            return False, []
        
        # Calcular tamaño mínimo para considerar éxito
        success_threshold = login_page_size + 500
        
        print(f"      📏 Success threshold: >{success_threshold} bytes (login page + 500)")
        
        # PASO 2: Crear wordlist combinada para FFUF
        combined_wordlist = create_combined_wordlist(username_list, password_list)
        
        # PASO 3: Crear archivo temporal para resultados JSON
        output_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        output_file.close()
        
        # COMANDO FFUF
        command = [
            "ffuf",
            "-u", target_url,
            "-w", combined_wordlist,
            "-X", "POST",
            "-d", f"{username_field}=FUZZUSER&{password_field}=FUZZPASS",
            "-H", "Content-Type: application/x-www-form-urlencoded",
            "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "-fs", f"{login_page_size}",
            "-o", output_file.name,
            "-of", "json",
            "-t", "1",
            "-p", "1.0",
            "-timeout", "10",
            "-s",
            "-k",
            "-r"
        ]
        
        # Verificar FFUF
        try:
            test_result = subprocess.run(["ffuf", "-h"], capture_output=True, text=True, timeout=5)
            if test_result.returncode != 0:
                print(f"      ❌ FFUF not working properly")
                return False, []
        except FileNotFoundError:
            print(f"      ❌ FFUF not found in PATH")
            return False, []
        
        # Mostrar comando completo
        cmd_display = " ".join(command)
        print(f"      💻 FFUF Command: {cmd_display}")
        print(f"      📏 Looking for responses > {success_threshold} bytes")
        
        # Ejecutar FFUF
        print(f"      🚀 Running FFUF attack...")
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        
        # Debug mínimo
        if result.returncode != 0 and result.stderr:
            print(f"      ⚠️  FFUF error: {result.stderr[:100]}")
        
        # Analizar resultados y obtener credenciales
        success, found_credentials = analyze_ffuf_results_with_credentials(output_file.name, login_page_size, success_threshold)
        
        return success, found_credentials
            
    except subprocess.TimeoutExpired:
        print(f"      ⏰ FFUF attack timed out")
        return False, []
    except Exception as e:
        print(f"      ❌ Unexpected error: {str(e)[:50]}")
        return False, []
    finally:
        # Cleanup
        try:
            if 'combined_wordlist' in locals():
                os.unlink(combined_wordlist)
            if 'output_file' in locals():
                os.unlink(output_file.name)
        except:
            pass


def analyze_ffuf_results_with_credentials(output_file, login_page_size, success_threshold):
    """Analyze FFUF results and return found credentials."""
    try:
        if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
            print(f"      ℹ️  No different responses found")
            return False, []
        
        with open(output_file, 'r') as f:
            content = f.read().strip()
            
        if not content:
            print(f"      ℹ️  FFUF found no different responses")
            return False, []
            
        try:
            results = json.loads(content)
        except json.JSONDecodeError:
            print(f"      ⚠️  Invalid FFUF output format")
            return False, []
        
        if 'results' not in results or not results['results']:
            print(f"      ℹ️  All responses had same size as login page")
            return False, []
        
        print(f"      🔍 Found {len(results['results'])} different responses")
        
        valid_credentials = []
        found_credentials = []  # Para retornar
        
        # Analizar por tamaño únicamente
        for result in results['results'][:10]:
            status = result.get('status', 0)
            length = result.get('length', 0)
            input_data = result.get('input', {})
            
            # Extraer credenciales
            credentials = "unknown:unknown"
            if input_data:
                for key, value in input_data.items():
                    if ':' in str(value):
                        credentials = str(value)
                        break
            
            # CRITERIO ÚNICO: Tamaño de respuesta
            if length >= success_threshold:
                print(f"      🎉 SUCCESS: {credentials} - Response size: {length} bytes (>{success_threshold})")
                valid_credentials.append(credentials)
                found_credentials.append(credentials)
            elif length > login_page_size:
                print(f"      🔍 POTENTIAL: {credentials} - Response size: {length} bytes (larger but < threshold)")
                valid_credentials.append(credentials)
                found_credentials.append(credentials)
            else:
                print(f"      ❌ Too small: {credentials} - Response size: {length} bytes")
        
        # Resumen
        if valid_credentials:
            print(f"      ✅ Found {len(valid_credentials)} valid/potential credential(s)")
            return True, found_credentials
        else:
            print(f"      ❌ No significantly larger responses found")
            return False, []
        
    except Exception as e:
        print(f"      ⚠️  Error analyzing results: {str(e)[:50]}")
        return False, []


# Agregar esta función al final del archivo, antes de las funciones de compatibilidad

def attack_hydra_service(target_ip, target_port, service, username_list, password_list):
    """Attack service using Hydra - returns success status and found credentials."""
    
    try:
        print(f"      🔧 Service: {service}")
        print(f"      📝 Testing {len(username_list)} × {len(password_list)} = {len(username_list) * len(password_list)} combinations")
        
        # Crear archivos de wordlist para Hydra
        username_file, password_file = create_wordlist_files(username_list, password_list)
        
        # Construir comando Hydra
        command = [
            "hydra",
            "-L", username_file,
            "-P", password_file,
            "-t", "4",  # 4 threads
            "-w", "3",  # 3 second timeout
            "-f",       # Stop on first success
            "-v",       # Verbose
            target_ip,
            "-s", str(target_port),
            service
        ]
        
        # Mostrar comando completo
        cmd_display = " ".join(command)
        print(f"      💻 Hydra Command: {cmd_display}")
        
        # Verificar si Hydra está disponible
        try:
            test_result = subprocess.run(["hydra", "-h"], capture_output=True, text=True, timeout=5)
            if test_result.returncode != 0:
                print(f"      ❌ Hydra not working properly")
                return False, []
        except FileNotFoundError:
            print(f"      ❌ Hydra not found in PATH")
            print(f"      💡 Install with: sudo apt install hydra")
            return False, []
        
        # Ejecutar Hydra
        print(f"      🚀 Running Hydra attack...")
        result = subprocess.run(command, capture_output=True, text=True, timeout=180)  # 3 minutos timeout
        
        # Analizar resultados de Hydra
        found_credentials = []
        success_found = False
        
        # Buscar patrones de éxito en la salida
        output_lines = result.stdout.split('\n')
        for line in output_lines:
            line = line.strip()
            
            # Patrones de éxito comunes en Hydra
            if "login:" in line.lower() and "password:" in line.lower():
                # Extraer credenciales del formato: [PORT][SERVICE] host: IP   login: USER   password: PASS
                try:
                    if "login:" in line and "password:" in line:
                        # Buscar login: y password: en la línea
                        login_start = line.find("login:") + 6
                        login_end = line.find("password:") - 3
                        password_start = line.find("password:") + 9
                        
                        if login_start > 5 and password_start > 8:
                            username = line[login_start:login_end].strip()
                            password = line[password_start:].strip()
                            
                            credentials = f"{username}:{password}"
                            found_credentials.append(credentials)
                            success_found = True
                            
                            print(f"      🎉 SUCCESS: {credentials}")
                except:
                    # Si falla el parsing, mostrar la línea completa
                    print(f"      🎉 SUCCESS: {line}")
                    found_credentials.append("success:found")
                    success_found = True
            
            # Otros patrones de éxito
            elif "valid password found" in line.lower():
                success_found = True
                print(f"      🎉 SUCCESS: Valid credentials found")
                if not found_credentials:
                    found_credentials.append("valid:credentials")
        
        # Verificar códigos de salida de Hydra
        if result.returncode == 0 and not success_found:
            # Hydra terminó correctamente pero buscar en stderr también
            if "valid password found" in result.stderr.lower():
                success_found = True
                print(f"      🎉 SUCCESS: Valid credentials found (stderr)")
                found_credentials.append("valid:credentials")
        
        if success_found:
            print(f"      ✅ Found {len(found_credentials)} valid credential(s)")
            return True, found_credentials
        else:
            print(f"      ❌ No valid credentials found")
            
            # Debug para errores comunes
            if result.returncode != 0:
                if "could not connect" in result.stderr.lower():
                    print(f"      ⚠️  Connection failed to {service} service")
                elif "unsupported service" in result.stderr.lower():
                    print(f"      ⚠️  Service {service} not supported by Hydra")
                elif result.stderr.strip():
                    error_msg = result.stderr.strip()[:80]
                    print(f"      ⚠️  Hydra error: {error_msg}")
            
            return False, []
            
    except subprocess.TimeoutExpired:
        print(f"      ⏰ Hydra attack timed out")
        return False, []
    except Exception as e:
        print(f"      ❌ Unexpected error: {str(e)[:50]}")
        return False, []
    finally:
        # Cleanup
        try:
            if 'username_file' in locals():
                os.unlink(username_file)
            if 'password_file' in locals():
                os.unlink(password_file)
        except:
            pass


# Mantener funciones de compatibilidad para otros servicios (no web forms)
def run_bruteforce(target, username_list, password_list, service):
    """Fallback to hydra for non-web services."""
    print(f"  ⚠️  Non-web service detected: {service}")
    print(f"  💡 FFUF is only for web forms, skipping...")
    return False


def check_port_connectivity(host, port, timeout=5):
    """Check if a port is open and accessible."""
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, int(port)))
        sock.close()
        return result == 0
    except:
        return False
