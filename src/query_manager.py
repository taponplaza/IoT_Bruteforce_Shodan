"""Query management and execution for Shodan searches."""

import yaml
from pathlib import Path
from shodan_analysis import run_basic_search, get_api_info
from data_manager import save_results_to_json
from config_manager import (
    AVAILABLE_QUERIES, ADVANCED_QUERIES_ES, ADVANCED_QUERY_NAMES, 
    ADVANCED_QUERY_DESCRIPTIONS, ADVANCED_QUERY_CREDITS, RESULT_LIMITS,
    estimate_credits_by_limit, calculate_total_cost, REPORT_NAMES
)

def get_result_limit():
    """Allow user to select result limit for basic queries (FREE)."""
    print("\n📊 RESULT LIMIT SELECTION")
    print("="*40)
    print("🆓 Consultas básicas son GRATUITAS independientemente del límite")
    print("💡 Recomendado: 100-300 para pruebas, 500+ para análisis completo")
    print()
    
    for key, limit in RESULT_LIMITS.items():
        if limit == "custom":
            print(f"{key}. Custom limit")
            print(f"   ⚙️  Define your own limit (up to 10,000)")
        else:
            print(f"{key}. {limit} results")
            print(f"   📊 Good for: {'testing' if limit <= 300 else 'comprehensive analysis'}")
    print()
    
    # Get user selection
    while True:
        selection = input(f"Select result limit (1-{len(RESULT_LIMITS)}): ")
        if selection in RESULT_LIMITS:
            selected_limit = RESULT_LIMITS[selection]
            if selected_limit == "custom":
                while True:
                    try:
                        custom_limit = int(input("Enter custom limit (1-10000): "))
                        if 1 <= custom_limit <= 10000:
                            return custom_limit
                        else:
                            print("Limit must be between 1 and 10,000")
                    except ValueError:
                        print("Invalid input. Please enter a number.")
            else:
                return selected_limit
        else:
            print(f"Invalid selection. Please choose 1-{len(RESULT_LIMITS)}")

def get_result_limit_advanced(query_selection):
    """Allow user to select result limit for advanced queries with detailed cost info."""
    print("\n📊 RESULT LIMIT SELECTION")
    print("="*50)
    print("💡 Costo por límite de resultados:")
    print("   🆓 Hasta 100 resultados: Gratis")
    print("   💳 101-200 resultados: +1 crédito")
    print("   💳 201-300 resultados: +2 créditos")
    print("   💳 301-400 resultados: +3 créditos")
    print("   💳 401-500 resultados: +4 créditos")
    print("   💳 500+ resultados: +1 crédito por cada 100 adicionales")
    print()
    
    base_cost = ADVANCED_QUERY_CREDITS.get(query_selection, 1)
    
    for key, limit in RESULT_LIMITS.items():
        if limit == "custom":
            print(f"{key}. Custom limit")
            print(f"   ⚙️  Define your own limit (cost calculated dynamically)")
        else:
            total_cost, base_cost_calc, limit_cost = calculate_total_cost(query_selection, limit)
            print(f"{key}. {limit} results")
            print(f"   💰 Total cost: {total_cost} crédito{'s' if total_cost > 1 else ''} (base: {base_cost_calc}, limit: {limit_cost})")
    print()
    
    # Get user selection
    while True:
        selection = input(f"Select result limit (1-{len(RESULT_LIMITS)}): ")
        if selection in RESULT_LIMITS:
            selected_limit = RESULT_LIMITS[selection]
            if selected_limit == "custom":
                while True:
                    try:
                        custom_limit = int(input("Enter custom limit (1-10000): "))
                        if 1 <= custom_limit <= 10000:
                            total_cost, base_cost_calc, limit_cost = calculate_total_cost(query_selection, custom_limit)
                            print(f"💰 Custom limit cost: {total_cost} crédito{'s' if total_cost > 1 else ''}")
                            return custom_limit
                        else:
                            print("Limit must be between 1 and 10,000")
                    except ValueError:
                        print("Invalid input. Please enter a number.")
            else:
                return selected_limit
        else:
            print(f"Invalid selection. Please choose 1-{len(RESULT_LIMITS)}")

def run_basic_queries(config):
    """Run basic Shodan queries."""
    print("\n=== Basic Shodan Queries (Free) ===")
    print("💡 Estas consultas utilizan los límites de búsqueda gratuita de Shodan")
    print("💾 Los resultados se guardarán automáticamente en JSON para análisis futuro")
    print()
    
    basic_queries = {k: v for k, v in AVAILABLE_QUERIES.items() if k != "5"}
    for key, query in basic_queries.items():
        # Add descriptions for basic queries
        descriptions = {
            "1": "Web cameras and surveillance devices",
            "2": "Raspberry Pi and IoT devices", 
            "3": "Devices with default/weak passwords",
            "4": "Industrial Control Systems (ICS/SCADA)"
        }
        description = descriptions.get(key, "")
        print(f"{key}. {query}")
        if description:
            print(f"   📝 {description}")
        print()
    
    # Get user selection
    while True:
        selection = input(f"Select query (1-4): ")
        if selection in basic_queries:
            selected_query = basic_queries[selection]
            break
        print("Invalid selection. Please choose 1-4")
    
    # Seleccionar límite de resultados para consultas básicas
    result_limit = get_result_limit()
    
    print(f"\n🎯 Running basic search for: {selected_query}")
    print(f"📊 Result limit: {result_limit}")
    print(f"💰 Cost: Free (uses Shodan's basic search limits)")
    
    # Execute basic query
    execute_basic_flow(selected_query, config, result_limit)

def run_advanced_queries(config):
    """Run advanced Shodan queries for Spain."""
    print("\n=== Advanced Shodan Queries for Spain (Uses Credits) ===")
    print("🎯 Consultas especializadas optimizadas con filtros de producto y categoría")
    print("🚫 Sin filtros de honeypot - resultados más limpios")
    print("💡 Consultas mejoradas con fabricantes y productos específicos")
    print("💾 Los resultados se guardarán automáticamente en JSON para análisis futuro")
    print()
    
    for key, query in ADVANCED_QUERIES_ES.items():
        query_name = ADVANCED_QUERY_NAMES[key]
        description = ADVANCED_QUERY_DESCRIPTIONS[key]
        base_credits = ADVANCED_QUERY_CREDITS[key]
        
        print(f"{key}. {query_name}")
        print(f"   📝 {description}")
        print(f"   💳 Base cost: {base_credits} crédito{'s' if base_credits > 1 else ''}")
        print(f'   🔍 Query: "{query}"')
        print()
    
    # Get user selection
    while True:
        selection = input(f"Select advanced query (1-{len(ADVANCED_QUERIES_ES)}): ")
        if selection in ADVANCED_QUERIES_ES:
            selected_query = ADVANCED_QUERIES_ES[selection]
            query_name = ADVANCED_QUERY_NAMES[selection]
            description = ADVANCED_QUERY_DESCRIPTIONS[selection]
            base_credits = ADVANCED_QUERY_CREDITS[selection]
            break
        print(f"Invalid selection. Please choose 1-{len(ADVANCED_QUERIES_ES)}")
    
    print(f"\n🎯 Selected: {query_name}")
    print(f"📝 Description: {description}")
    print(f"💳 Base cost: {base_credits} crédito{'s' if base_credits > 1 else ''}")
    print(f'🔍 Query: "{selected_query}"')
    
    # Seleccionar límite de resultados con costo detallado
    result_limit = get_result_limit_advanced(selection)
    
    # Calculate total cost
    total_cost, base_cost, limit_cost = calculate_total_cost(selection, result_limit)
    
    print(f"\n📊 Query configuration:")
    print(f"   🔍 Search query: \"{selected_query}\"")
    print(f"   📊 Result limit: {result_limit}")
    print(f"💰 Cost breakdown:")
    print(f"   🔹 Base query cost: {base_cost} crédito{'s' if base_cost > 1 else ''}")
    print(f"   🔹 Result limit cost: {limit_cost} crédito{'s' if limit_cost > 1 else ''} (for {result_limit} results)")
    print(f"   🔹 Total cost: {total_cost} crédito{'s' if total_cost > 1 else ''}")
    
    # Show current credits and confirm
    credits_info = get_api_info(config["shodan_api_key"])
    current_credits = credits_info['credits_remaining']
    
    print(f"\n💳 Current Shodan credits: {current_credits}")
    
    if total_cost > current_credits:
        print(f"❌ Insufficient credits! You need {total_cost} but only have {current_credits}")
        return
    
    confirm = input(f"\n❓ This query will cost {total_cost} crédito{'s' if total_cost > 1 else ''}. Continue? (y/n): ")
    if confirm.lower() != 'y':
        print("🚫 Search cancelled.")
        return
    
    # Execute advanced query
    execute_advanced_flow(selected_query, query_name, config, result_limit, selection)

def execute_basic_flow(selected_query, config, result_limit=None):
    """Execute basic query flow."""
    # Create reports directory if it doesn't exist
    reports_dir = Path(__file__).resolve().parents[1] / "reports"
    reports_dir.mkdir(exist_ok=True)
    
    # Generate output path with specific name
    report_filename = REPORT_NAMES[selected_query]
    output_path = reports_dir / report_filename
    
    print(f"\n🔍 Executing Shodan search...")
    print(f"📄 Report will be saved to: {output_path}")
    if result_limit:
        print(f"📊 Result limit: {result_limit}")
    
    # Run basic search and generate report
    results, targets = run_basic_search(selected_query, str(output_path), config["shodan_api_key"], limit=result_limit)

    # Show results
    if results and targets:
        print(f"\n✅ Search completed!")
        print(f"📱 Devices found: {len(targets)}")
        print(f"📄 Report generated: {output_path}")
        
        # Guardar en JSON para consultas básicas
        json_path = save_results_to_json(results, targets, selected_query)
        print(f"💾 Results saved to JSON for future analysis")
        
        # Show available credits
        credits_info = get_api_info(config["shodan_api_key"])
        print(f"💳 Shodan credits remaining: {credits_info['credits_remaining']}")

        # Continue with brute force flow usando attack_executor
        from attack_executor import execute_brute_force_flow
        execute_brute_force_flow(targets)
    else:
        print("❌ No devices found.")

def execute_advanced_flow(query, query_name, config, result_limit, query_key):
    """Execute advanced query flow with JSON saving."""
    # Calculate cost information
    total_cost, base_cost, limit_cost = calculate_total_cost(query_key, result_limit)
    cost_info = {
        "base_cost": base_cost,
        "limit_cost": limit_cost,
        "total_cost": total_cost,
        "result_limit": result_limit
    }
    
    # Create reports directory
    reports_dir = Path(__file__).resolve().parents[1] / "reports"
    reports_dir.mkdir(exist_ok=True)
    
    # Generate output path
    report_filename = f"{query_name}_report.html"
    output_path = reports_dir / report_filename
    
    print(f"\n🔍 Executing Shodan search...")
    print(f"📄 Report will be saved to: {output_path}")
    print(f"📊 Result limit: {result_limit}")
    
    # Run search
    results, targets = run_basic_search(query, str(output_path), config["shodan_api_key"], limit=result_limit)
    
    if not results or not targets:
        print("❌ No devices found.")
        return
    
    # Save to JSON with cost info
    json_path = save_results_to_json(results, targets, query_name, cost_info)
    
    # Show results summary
    print(f"\n✅ Search completed!")
    print(f"📱 Devices found: {len(targets)}")
    print(f"📊 Results limited to: {result_limit}")
    print(f"💰 Actual cost: {cost_info['total_cost']} crédito{'s' if cost_info['total_cost'] > 1 else ''}")
    print(f"📄 Report generated: {output_path}")
    print(f"💾 Results saved to JSON for future use without credit cost")
    
    # Show credits after search
    credits_info = get_api_info(config["shodan_api_key"])
    print(f"💳 Shodan credits remaining: {credits_info['credits_remaining']}")
    
    # Continue with brute force flow usando attack_executor
    from attack_executor import execute_brute_force_flow
    execute_brute_force_flow(targets)