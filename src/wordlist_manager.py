"""Wordlist management and recommendations for brute force attacks."""

# Importar las constantes del config_manager
from config_manager import WORDLISTS

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
        
        # Show security assessment
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
    
    # Apply safety limit (max 100 combinations)
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
    """Analyze targets and recommend best wordlist based on detected services."""
    print("\n🤖 WORDLIST RECOMMENDATIONS")
    print("="*50)
    
    # Analyze target characteristics
    service_types = {}
    products = {}
    
    for target in targets:
        # Service analysis by port
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
    
    # Check each category
    ics_count = service_types.get('ics', 0) + products.get('ics', 0)
    if ics_count > 0:
        recommendations.append((2, f"🏭 ICS/SCADA Systems - {ics_count} devices detected"))
    
    camera_count = service_types.get('camera', 0) + products.get('camera', 0)
    if camera_count > 0:
        recommendations.append((3, f"📹 IP Cameras - {camera_count} devices detected"))
    
    remote_count = service_types.get('remote', 0)
    if remote_count > 0:
        recommendations.append((4, f"🔐 Remote Access - {remote_count} devices detected"))
    
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