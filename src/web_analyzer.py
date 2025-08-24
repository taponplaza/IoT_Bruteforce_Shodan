"""Simple web form detection focused on POST forms for FFUF."""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning

warnings.simplefilter('ignore', InsecureRequestWarning)

class WebFormAnalyzer:
    """Analyzes web pages for POST forms only - optimized for FFUF."""
    
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        }
    
    def analyze_website(self, ip, port, use_ssl=False):
        """Analyze website for POST forms - FFUF compatible."""
        protocol = "https" if use_ssl else "http"
        base_url = f"{protocol}://{ip}:{port}"
        
        try:
            response = requests.get(
                base_url, 
                headers=self.headers, 
                timeout=5, 
                verify=False,
                allow_redirects=True
            )
            
            if response.status_code == 200:
                form_info = self._extract_login_form(response.text, base_url)
                
                if form_info and form_info['method'].lower() == 'post':
                    form_info['base_url'] = base_url
                    
                    print(f"      ✅ POST form: {form_info['username_field']}/{form_info['password_field']}")
                    
                    return form_info
                    
            return None
                
        except Exception:
            return None

    def _extract_login_form(self, html_content, url):
        """Extract login form details from HTML."""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                password_inputs = form.find_all('input', {'type': 'password'})
                if not password_inputs:
                    continue
                
                password_field = password_inputs[0].get('name', 'password')
                
                # Find username field
                username_field = None
                inputs = form.find_all('input')
                
                for input_field in inputs:
                    input_type = input_field.get('type', '').lower()
                    name = input_field.get('name', '').lower()
                    
                    if input_type in ['text', 'email'] or 'user' in name or 'email' in name:
                        username_field = input_field.get('name')
                        break
                
                if not username_field:
                    username_field = 'username'
                
                method = form.get('method', 'post').lower()
                action = form.get('action', '')
                
                if action:
                    action = urljoin(url, action)
                else:
                    action = url
                
                return {
                    'method': method,
                    'action': action,
                    'username_field': username_field,
                    'password_field': password_field,
                    'failure_text': 'ffuf_size_based'  # Identificador para FFUF
                }
            
            return None
            
        except Exception:
            return None
    
    def analyze_website_robust(self, host, port, use_ssl=False, timeout=15):
        """Analyze website with improved error handling for non-standard ports."""
        try:
            protocol = "https" if use_ssl else "http"
            base_url = f"{protocol}://{host}:{port}"
            
            print(f"      🌐 Connecting to {base_url}...")
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
            
            response = requests.get(
                base_url,
                headers=headers,
                timeout=timeout,
                verify=False,
                allow_redirects=True
            )
            
            if response.status_code not in [200, 301, 302]:
                print(f"      ⚠️  HTTP {response.status_code} - trying alternative paths...")
                
                # Intentar paths comunes
                common_paths = ['/admin', '/login', '/console', '/manager', '/portal']
                for path in common_paths:
                    try:
                        alt_response = requests.get(
                            f"{base_url}{path}",
                            headers=headers,
                            timeout=10,
                            verify=False,
                            allow_redirects=True
                        )
                        if alt_response.status_code == 200:
                            print(f"      ✅ Found accessible path: {path}")
                            response = alt_response
                            base_url = f"{base_url}{path}"
                            break
                    except:
                        continue
            
            # Analizar contenido
            soup = BeautifulSoup(response.content, 'html.parser')
            forms = soup.find_all('form')
            
            print(f"      📋 Found {len(forms)} form(s) on the page")
            
            for i, form in enumerate(forms):
                method = form.get('method', 'get').lower()
                action = form.get('action', '')
                
                print(f"      📝 Form {i+1}: Method={method}, Action={action}")
                
                if method == 'post':
                    # Buscar campos de entrada
                    input_fields = form.find_all(['input', 'select', 'textarea'])
                    
                    username_field = None
                    password_field = None
                    
                    for field in input_fields:
                        field_type = field.get('type', '').lower()
                        field_name = field.get('name', '').lower()
                        field_id = field.get('id', '').lower()
                        
                        # Detectar campo de usuario
                        if (field_type in ['text', 'email'] or 
                            any(keyword in field_name for keyword in ['user', 'login', 'email', 'username']) or
                            any(keyword in field_id for keyword in ['user', 'login', 'email', 'username'])):
                            username_field = field.get('name') or field.get('id')
                            print(f"      👤 Username field: {username_field}")
                        
                        # Detectar campo de contraseña
                        elif (field_type == 'password' or
                              any(keyword in field_name for keyword in ['pass', 'pwd', 'password']) or
                              any(keyword in field_id for keyword in ['pass', 'pwd', 'password'])):
                            password_field = field.get('name') or field.get('id')
                            print(f"      🔒 Password field: {password_field}")
                    
                    if username_field and password_field:
                        # Resolver action URL
                        if action.startswith('http'):
                            action_url = action
                        elif action.startswith('/'):
                            action_url = f"{protocol}://{host}:{port}{action}"
                        elif action:
                            action_url = f"{base_url}/{action}"
                        else:
                            action_url = base_url
                        
                        print(f"      ✅ POST form: {username_field}/{password_field}")
                        
                        return {
                            'action': action_url,
                            'base_url': base_url,
                            'method': 'post',
                            'username_field': username_field,
                            'password_field': password_field
                        }
            
            print(f"      ❌ No POST forms with login fields found")
            return None
            
        except requests.exceptions.Timeout:
            print(f"      ⏰ Connection timeout to {host}:{port}")
            return None
        except requests.exceptions.ConnectionError:
            print(f"      🔌 Connection failed to {host}:{port}")
            return None
        except requests.exceptions.SSLError:
            print(f"      🔒 SSL error - trying HTTP instead...")
            if use_ssl:
                return self.analyze_website_robust(host, port, use_ssl=False, timeout=timeout)
            return None
        except Exception as e:
            print(f"      ❌ Error analyzing {host}:{port}: {str(e)[:50]}")
            return None