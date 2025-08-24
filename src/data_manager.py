"""Data management for loading and saving JSON results."""

import json
import os
from pathlib import Path
from datetime import datetime

# Importar constantes del config_manager
from config_manager import ADVANCED_QUERY_NAMES, ADVANCED_QUERY_DESCRIPTIONS, ADVANCED_QUERIES_ES

def save_results_to_json(results, targets, query_name, cost_info=None):
    """Save Shodan results to JSON file - EXACTO del original."""
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
    """Load previous Shodan results from JSON file - EXACTO del original."""
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

def run_from_previous_results():
    """Load and attack previous results - USANDO MÓDULOS NUEVOS."""
    results, targets = load_results_from_json()
    
    if results and targets:
        # NUEVO: Usar el módulo attack_executor completamente modular
        from attack_executor import execute_brute_force_flow
        execute_brute_force_flow(targets)
    else:
        print("❌ Failed to load previous results.")