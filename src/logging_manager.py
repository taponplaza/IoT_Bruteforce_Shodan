"""Output logging manager for saving program output to file."""

import sys
import os
from datetime import datetime
from pathlib import Path

class OutputLogger:
    """Class to capture and optionally save program output to file."""
    
    def __init__(self, save_output=False, log_filename=None):
        self.save_output = save_output
        self.original_stdout = sys.stdout
        self.log_file = None
        
        if save_output:
            # Create logs directory
            logs_dir = Path(__file__).resolve().parents[1] / "logs"
            logs_dir.mkdir(exist_ok=True)
            
            # Generate filename if not provided
            if not log_filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                log_filename = f"shodan_bruteforce_{timestamp}.txt"
            
            self.log_path = logs_dir / log_filename
            
            # Open log file
            try:
                self.log_file = open(self.log_path, 'w', encoding='utf-8')
                print(f"📝 Output will be saved to: {self.log_path}")
                print("="*60)
            except Exception as e:
                print(f"❌ Error creating log file: {e}")
                self.save_output = False
        
        # Redirect stdout if logging is enabled
        if self.save_output and self.log_file:
            sys.stdout = self
    
    def write(self, text):
        """Write to both console and file."""
        # Write to console
        self.original_stdout.write(text)
        self.original_stdout.flush()
        
        # Write to file if enabled
        if self.save_output and self.log_file:
            try:
                self.log_file.write(text)
                self.log_file.flush()
            except:
                pass  # Silently ignore file write errors
    
    def flush(self):
        """Flush both outputs."""
        self.original_stdout.flush()
        if self.save_output and self.log_file:
            try:
                self.log_file.flush()
            except:
                pass
    
    def close(self):
        """Close log file and restore stdout."""
        if self.save_output and self.log_file:
            try:
                # Write final summary
                self.log_file.write(f"\n{'='*60}\n")
                self.log_file.write(f"Log ended at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                self.log_file.write(f"{'='*60}\n")
                
                self.log_file.close()
                print(f"\n📝 Output saved to: {self.log_path}")
            except Exception as e:
                print(f"❌ Error closing log file: {e}")
        
        # Restore original stdout
        sys.stdout = self.original_stdout

def setup_output_logging():
    """Setup output logging based on user preference."""
    print("="*60)
    print("SHODAN IoT/ICS BRUTE FORCE TOOL")
    print("="*60)
    print("📝 Output Logging Options")
    print()
    print("1. Console output only (default)")
    print("2. Save output to file + console")
    print("3. Save output to custom filename + console")
    print()
    
    while True:
        choice = input("Select output option (1-3, or press Enter for 1): ").strip()
        
        if choice == "" or choice == "1":
            print("✅ Using console output only")
            return OutputLogger(save_output=False)
            
        elif choice == "2":
            print("✅ Output will be saved to auto-generated filename")
            return OutputLogger(save_output=True)
            
        elif choice == "3":
            custom_name = input("Enter filename (without extension): ").strip()
            if custom_name:
                if not custom_name.endswith('.txt'):
                    custom_name += '.txt'
                print(f"✅ Output will be saved to: {custom_name}")
                return OutputLogger(save_output=True, log_filename=custom_name)
            else:
                print("❌ Invalid filename. Using auto-generated filename.")
                return OutputLogger(save_output=True)
        else:
            print("Invalid selection. Please choose 1-3")