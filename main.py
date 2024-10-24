import os
from typing import Optional, Dict
from email import message
import json
from colorama import Fore, Style, init
import logging
from email_header_analyzer import EmailHeaderAnalyzer
from url_ip_and_attachment_reputation_analysis import ReputationAnalyzer
from email_ioc_analyzer import EmailIOCAnalyzer

class EmailAnalyzer:
    def __init__(self):
        """Initialize the main EmailAnalyzer class"""
        init(autoreset=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        self.header_analyzer = EmailHeaderAnalyzer()
        self.ioc_analyzer = EmailIOCAnalyzer()
        self.reputation_analyzer = None
        
        # Create necessary directories
        self.cache_dir = "cache"
        self.attachments_dir = "attachments"
        self.config_file = "config.json"
        
        for directory in [self.cache_dir, self.attachments_dir]:
            if not os.path.exists(directory):
                os.makedirs(directory)

    def load_config(self) -> Dict[str, str]:
        """Load API keys from config file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            self.logger.error(f"{Fore.RED}Error loading config: {e}{Style.RESET_ALL}")
            return {}

    def save_config(self, config: Dict[str, str]) -> None:
        """Save API keys to config file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f)
        except Exception as e:
            self.logger.error(f"{Fore.RED}Error saving config: {e}{Style.RESET_ALL}")

    def initialize_reputation_analyzer(self) -> None:
        """Initialize the ReputationAnalyzer with API keys"""
        config = self.load_config()
        
        # If we don't have API keys saved, prompt for them
        if not config.get('vt_api_key'):
            print(f"\n{Fore.YELLOW}VirusTotal API key not found in config.{Style.RESET_ALL}")
            vt_api_key = input("Enter your VirusTotal API key (press Enter to skip): ").strip()
            if vt_api_key:
                config['vt_api_key'] = vt_api_key
        
        if not config.get('abuse_api_key'):
            print(f"\n{Fore.YELLOW}AbuseIPDB API key not found in config.{Style.RESET_ALL}")
            abuse_api_key = input("Enter your AbuseIPDB API key (press Enter to skip): ").strip()
            if abuse_api_key:
                config['abuse_api_key'] = abuse_api_key
        
        # Save config if we got any new API keys
        if config:
            self.save_config(config)
        
        # Initialize ReputationAnalyzer with available API keys
        self.reputation_analyzer = ReputationAnalyzer(
            vt_api_key=config.get('vt_api_key'),
            abuse_api_key=config.get('abuse_api_key'),
            cache_dir=self.cache_dir
        )

    def analyze_email(self, eml_path: str) -> None:
        """Main method to analyze an email file"""
        try:
            # Load email message
            msg = self.header_analyzer.load_email(eml_path)
            if not msg:
                return

            while True:
                print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}Email Analysis Menu{Style.RESET_ALL}")
                print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
                print("1. Print Important Headers")
                print("2. Print Security Headers")
                print("3. Analyze URLs, IPs, and Attachments")
                print("4. Show IOCs Analysis")
                print("5. Another Email")
                print("6. Exit")
                
                choice = input("\nEnter your choice (1-6): ").strip()
                
                if choice == '1':
                    self.header_analyzer.print_important_headers(eml_path)
                
                elif choice == '2':
                    self.header_analyzer.print_security_headers(msg)
                
                elif choice == '3':
                    if not self.reputation_analyzer:
                        self.initialize_reputation_analyzer()
                    self.reputation_analyzer.analyze_email_content(msg, self.attachments_dir)
                
                elif choice == '4':
                    iocs = self.ioc_analyzer.extract_iocs(msg)
                    self.ioc_analyzer.print_analysis_results(iocs)
                
                elif choice == '5':
                    return
                
                elif choice == '6':
                    print(f"\n{Fore.GREEN}Thank you for using Email Analyzer!{Style.RESET_ALL}")
                    exit(0)
                
                else:
                    print(f"\n{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")

        except Exception as e:
            self.logger.error(f"{Fore.RED}Error analyzing email: {e}{Style.RESET_ALL}")

def main():
    """Main entry point of the application"""
    analyzer = EmailAnalyzer()
    
    print(f"{Fore.CYAN}Welcome to Email Analyzer!{Style.RESET_ALL}")
    
    while True:
        print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Please provide the path to an .eml file{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        
        eml_path = input("\nEnter path to .eml file (or 'q' to quit): ").strip()
        
        if eml_path.lower() == 'q':
            print(f"\n{Fore.GREEN}Thank you for using Email Analyzer!{Style.RESET_ALL}")
            break
            
        if not os.path.exists(eml_path):
            print(f"\n{Fore.RED}File not found: {eml_path}{Style.RESET_ALL}")
            continue
            
        if not eml_path.lower().endswith('.eml'):
            print(f"\n{Fore.RED}File must be an .eml file{Style.RESET_ALL}")
            continue
            
        analyzer.analyze_email(eml_path)

if __name__ == "__main__":
    main()
