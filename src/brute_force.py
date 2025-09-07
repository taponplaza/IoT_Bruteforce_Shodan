"""Module to perform brute force against web forms using FFUF and services using Hydra."""

# Asegurar que estos imports estén al principio del archivo

import subprocess
import tempfile
import os
import json
import socket
import warnings
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

warnings.simplefilter('ignore', InsecureRequestWarning)

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
        
        # PASO 1: Verificar conectividad básica del puerto
        if not check_port_connectivity(target_ip, target_port, timeout=5):
            print(f"      ❌ Port {target_port} not accessible on {target_ip}")
            print(f"      💡 Host may be down, firewalled, or service not running")
            return False, []
        
        # PASO 2: Verificar Hydra installation (UNA SOLA VEZ)
        try:
            which_result = subprocess.run(["which", "hydra"], capture_output=True, text=True, timeout=5)
            if which_result.returncode != 0:
                print(f"      ❌ Hydra not found in PATH")
                print(f"      💡 Install with: sudo apt install hydra")
                return False, []
            
            print(f"      ✅ Hydra found at: {which_result.stdout.strip()}")
            
        except FileNotFoundError:
            print(f"      ❌ 'which' command not available")
            return False, []
        except Exception as e:
            print(f"      ⚠️  Error checking Hydra: {str(e)[:50]}")
            return False, []
        
        # PASO 3: Crear archivos de wordlist
        username_file, password_file = create_wordlist_files(username_list, password_list)
        
        # PASO 4: Comando Hydra optimizado
        command = [
            "hydra",
            "-L", username_file,
            "-P", password_file,
            "-t", "1",  # Single thread para evitar detección
            "-w", "10", # 10 segundos timeout
            "-f",       # Stop on first success
            "-q",       # Quiet mode
            "-s", str(target_port),
            target_ip,
            service
        ]
        
        cmd_display = f"hydra -L users.txt -P pass.txt -t 1 -w 10 -f -q -s {target_port} {target_ip} {service}"
        print(f"      💻 Hydra Command: {cmd_display}")
        
        # PASO 5: Ejecutar Hydra
        print(f"      🚀 Running Hydra attack...")
        result = subprocess.run(command, capture_output=True, text=True, timeout=180)
        
        print(f"      📊 Exit code: {result.returncode}")
        
        # PASO 6: Analizar errores específicos PRIMERO
        if result.stderr:
            stderr_lower = result.stderr.lower()
            
            # SSH key-only authentication
            if "does not support password authentication" in stderr_lower or "method reply 4" in stderr_lower:
                print(f"      🔐 SSH Key-Only Authentication detected")
                print(f"      💡 This server only accepts SSH key authentication (no passwords)")
                print(f"      ❌ Password brute force not possible on this target")
                return False, []
            
            # Connection errors
            elif any(error in stderr_lower for error in ["could not connect", "connection refused", "Connection timed out", "timeout"]):
                print(f"      🔌 Connection failed - service may be down or filtered")
                return False, []
            
            # Network errors
            elif any(error in stderr_lower for error in ["network unreachable", "could not resolve"]):
                print(f"      🌐 Network error - host may be unreachable")
                return False, []
            
            # Permission/access errors
            elif "permission denied" in stderr_lower:
                print(f"      🛡️  Permission denied - service may be restricted")
                return False, []
            
            # Service not supported
            elif any(error in stderr_lower for error in ["unsupported service", "unknown service"]):
                print(f"      🚫 Service {service} not supported by Hydra")
                return False, []
            
            # Mostrar error específico si no coincide con ningún patrón conocido
            else:
                stderr_preview = result.stderr.strip()[:150]
                print(f"      🔍 Error: {stderr_preview}")
        
        # PASO 7: Analizar ÉXITO - LÓGICA CORREGIDA
        found_credentials = []
        success_found = False
        
        # Analizar tanto stdout como stderr para encontrar credenciales
        all_output = (result.stdout + "\n" + (result.stderr or "")).lower()
        output_lines = (result.stdout + "\n" + (result.stderr or "")).split('\n')
        
        for line in output_lines:
            line = line.strip()
            if not line:
                continue
                
            # PATRONES DE ÉXITO REALES - Solo líneas que contienen credenciales válidas
            if "login:" in line and "password:" in line:
                # Verificar que NO contenga "0 valid password" o "0 password found"
                if "0 valid password" not in line.lower() and "0 password found" not in line.lower():
                    try:
                        # Formato típico: [22][ssh] host: IP   login: user   password: pass
                        login_match = line.find("login:")
                        password_match = line.find("password:")
                        
                        if login_match != -1 and password_match != -1:
                            login_part = line[login_match + 6:password_match].strip()
                            password_part = line[password_match + 9:].strip()
                            
                            # Verificar que no estén vacíos
                            if login_part and password_part:
                                credentials = f"{login_part}:{password_part}"
                                found_credentials.append(credentials)
                                success_found = True
                                print(f"      🎉 SUCCESS: {credentials}")
                    except Exception:
                        pass
        
        # VERIFICAR PATRONES DE NO-ÉXITO
        if any(pattern in all_output for pattern in [
            "0 valid password found",
            "0 password found", 
            "0 of ",
            "no login/password found",
            "0 valid passwords found"
        ]):
            print(f"      ❌ No valid credentials found")
            return False, []
        
        # VERIFICAR CÓDIGOS DE SALIDA
        if result.returncode == 0 and success_found:
            print(f"      ✅ Found {len(found_credentials)} valid credential(s)")
            return True, found_credentials
        elif result.returncode == 0 and not success_found:
            print(f"      ❌ Attack completed but no valid credentials found")
            return False, []
        elif result.returncode == 1:
            print(f"      ❌ No valid credentials found")
            return False, []
        elif result.returncode == 2:
            print(f"      ❌ Connection/service error")
            return False, []
        elif result.returncode == 255:
            print(f"      ❌ General Hydra error")
            return False, []
        else:
            print(f"      ❌ Unknown error (exit code {result.returncode})")
            return False, []
            
    except subprocess.TimeoutExpired:
        print(f"      ⏰ Hydra attack timed out (3 minutes)")
        return False, []
    except Exception as e:
        print(f"      ❌ Unexpected error: {str(e)}")
        return False, []
    finally:
        # Cleanup
        try:
            if 'username_file' in locals() and os.path.exists(username_file):
                os.unlink(username_file)
            if 'password_file' in locals() and os.path.exists(password_file):
                os.unlink(password_file)
        except:
            pass

def check_port_connectivity(host, port, timeout=5):
    """Check if a port is open and accessible."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, int(port)))
        sock.close()
        
        if result == 0:
            print(f"      ✅ Port {port} is accessible")
            return True
        else:
            print(f"      ❌ Port {port} not accessible (connection failed)")
            return False
    except socket.gaierror as e:
        print(f"      ❌ DNS resolution failed: {e}")
        return False
    except socket.timeout:
        print(f"      ❌ Connection timeout")
        return False
    except Exception as e:
        print(f"      ❌ Connection error: {e}")
        return False
