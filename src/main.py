"""Main entry point for the application - COMPLETELY MODULAR."""

import yaml
import atexit
from pathlib import Path
from config_manager import create_directories
from data_manager import run_from_previous_results
from query_manager import run_basic_queries, run_advanced_queries
from logging_manager import setup_output_logging

def main():
    """Main entry point - FULLY MODULAR with output logging."""
    
    # Setup output logging FIRST
    logger = setup_output_logging()
    
    # Register cleanup function
    atexit.register(lambda: logger.close())
    
    # Create necessary directories
    create_directories()
    
    # Load config
    base_dir = Path(__file__).resolve().parents[1]
    config_path = base_dir / "config" / "config.yaml"
    
    try:
        with open(config_path) as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"❌ Config file not found: {config_path}")
        print("Please ensure config/config.yaml exists with your Shodan API key.")
        return
    except Exception as e:
        print(f"❌ Error loading config: {e}")
        return

    # Show main options
    print("\n" + "="*60)
    print("MAIN MENU")
    print("="*60)
    print("🔍 Fully modular system - no legacy dependencies")
    print("📦 All components are independent and reusable")
    print("="*60)
    print()
    print("1. Run basic queries (free) 🆓")
    print("   └─ Webcams, Raspberry Pi, Default passwords, ICS")
    print()
    print("2. Run advanced queries for Spain (uses credits) 💳")
    print("   └─ Industrial systems, protocols, cameras, web interfaces")
    print()
    print("3. Load previous results and attack 📂")
    print("   └─ Analyze saved JSON files and run brute force")
    print()
    
    # Get main selection
    while True:
        main_choice = input("Select option (1-3): ")
        if main_choice in ["1", "2", "3"]:
            break
        print("Invalid selection. Please choose 1-3")
    
    # Execute selected option using ONLY modular components
    print(f"\n🚀 Executing option {main_choice} using modular system...")
    
    try:
        if main_choice == "1":
            print("📡 Loading basic query manager...")
            run_basic_queries(config)
            
        elif main_choice == "2":
            print("🎯 Loading advanced query manager...")
            run_advanced_queries(config)
            
        elif main_choice == "3":
            print("📂 Loading data manager...")
            run_from_previous_results()

        print("\n🎉 Execution completed using fully modular system!")
        print("📋 Components used:")
        print("   ├─ config_manager.py - Configuration and constants")
        print("   ├─ query_manager.py - Shodan query execution") 
        print("   ├─ data_manager.py - JSON data management")
        print("   ├─ wordlist_manager.py - Credential wordlists")
        print("   ├─ service_detector.py - Service detection")
        print("   ├─ attack_executor.py - Brute force orchestration")
        print("   ├─ brute_force.py - FFUF/Hydra attack execution")
        print("   └─ logging_manager.py - Output logging")
        
    except KeyboardInterrupt:
        print("\n⚠️  Program interrupted by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
    finally:
        # Logger cleanup will be handled by atexit
        pass

if __name__ == "__main__":
    main()