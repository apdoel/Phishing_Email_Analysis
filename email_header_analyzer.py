import email
from email import policy
import socket
from colorama import Fore, Style, init
from typing import Dict, Optional, List
import os
import logging

class EmailHeaderAnalyzer:
    def __init__(self):
        """Initialize the EmailHeaderAnalyzer with colorama and logging setup"""
        # Initialize colorama for cross-platform colored output
        init(autoreset=True)
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def load_email(self, eml_path: str) -> Optional[email.message.EmailMessage]:
        """
        Load an email file and return an EmailMessage object
        
        Args:
            eml_path (str): Path to the .eml file
            
        Returns:
            Optional[email.message.EmailMessage]: Parsed email message or None if error occurs
        """
        try:
            if not os.path.exists(eml_path):
                raise FileNotFoundError(f"Email file not found: {eml_path}")
                
            with open(eml_path, 'rb') as f:
                return email.message_from_binary_file(f, policy=policy.default)
                
        except FileNotFoundError as e:
            self.logger.error(f"{Fore.RED}File not found error: {e}{Style.RESET_ALL}")
            return None
        except Exception as e:
            self.logger.error(f"{Fore.RED}Error loading email: {e}{Style.RESET_ALL}")
            return None

    def get_sender_ip(self, msg: email.message.EmailMessage) -> Optional[str]:
        """
        Extract sender IP from Received headers
        
        Args:
            msg (email.message.EmailMessage): Email message object
            
        Returns:
            Optional[str]: Sender IP address or None if not found
        """
        try:
            received_headers = msg.get_all('Received', [])
            for header in received_headers:
                # Look for IP addresses in brackets
                start = header.find('[')
                end = header.find(']')
                if start != -1 and end != -1:
                    return header[start + 1:end]
            return None
        except Exception as e:
            self.logger.error(f"{Fore.RED}Error extracting sender IP: {e}{Style.RESET_ALL}")
            return None

    def reverse_dns_lookup(self, ip: str) -> Optional[str]:
        """
        Perform reverse DNS lookup for an IP address
        
        Args:
            ip (str): IP address to lookup
            
        Returns:
            Optional[str]: Hostname or None if lookup fails
        """
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror) as e:
            self.logger.warning(f"{Fore.YELLOW}Reverse DNS lookup failed: {e}{Style.RESET_ALL}")
            return None
        except Exception as e:
            self.logger.error(f"{Fore.RED}Error in reverse DNS lookup: {e}{Style.RESET_ALL}")
            return None

    def get_recipients(self, msg: email.message.EmailMessage) -> Dict[str, List[str]]:
        """
        Get all recipient addresses from To, CC, and BCC fields
        
        Args:
            msg (email.message.EmailMessage): Email message object
            
        Returns:
            Dict[str, List[str]]: Dictionary containing lists of recipients by type
        """
        recipients = {
            'to': [],
            'cc': [],
            'bcc': []
        }
        
        try:
            for field in ['to', 'cc', 'bcc']:
                addresses = msg.get_all(field, [])
                if addresses:
                    recipients[field] = [addr.strip() for addr in addresses]
        except Exception as e:
            self.logger.error(f"{Fore.RED}Error extracting recipients: {e}{Style.RESET_ALL}")
        
        return recipients

    def print_important_headers(self, eml_path: str) -> bool:
        """
        Print all important headers from the email file
        
        Args:
            eml_path (str): Path to the .eml file
            
        Returns:
            bool: True if successful, False otherwise
        """
        msg = self.load_email(eml_path)
        if not msg:
            return False

        try:
            # Print header section
            print(f"\n{Fore.CYAN}={'='*50}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Important Email Headers{Style.RESET_ALL}")
            print(f"{Fore.CYAN}={'='*50}{Style.RESET_ALL}\n")

            # Sender Information
            print(f"{Fore.GREEN}From:{Style.RESET_ALL} {msg.get('From', 'Not Available')}")
            
            sender_ip = self.get_sender_ip(msg)
            if sender_ip:
                print(f"{Fore.GREEN}Sender IP:{Style.RESET_ALL} {sender_ip}")
                hostname = self.reverse_dns_lookup(sender_ip)
                if hostname:
                    print(f"{Fore.GREEN}Reverse DNS:{Style.RESET_ALL} {hostname}")

            # Subject
            print(f"{Fore.GREEN}Subject:{Style.RESET_ALL} {msg.get('Subject', 'Not Available')}")

            # Recipients
            recipients = self.get_recipients(msg)
            for field, addresses in recipients.items():
                if addresses:
                    print(f"{Fore.GREEN}{field.upper()}:{Style.RESET_ALL} {', '.join(addresses)}")

            # Reply-To
            reply_to = msg.get('Reply-To')
            if reply_to:
                print(f"{Fore.GREEN}Reply-To:{Style.RESET_ALL} {reply_to}")

            # Date/Time
            print(f"{Fore.GREEN}Date:{Style.RESET_ALL} {msg.get('Date', 'Not Available')}")

            return True

        except Exception as e:
            self.logger.error(f"{Fore.RED}Error printing headers: {e}{Style.RESET_ALL}")
            return False

    def print_security_headers(self, msg: email.message.EmailMessage) -> bool:
        """
        Print security-related headers (SPF, DKIM, DMARC)
        
        Args:
            msg (email.message.EmailMessage): Email message object
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            print(f"\n{Fore.CYAN}={'='*50}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Security Headers{Style.RESET_ALL}")
            print(f"{Fore.CYAN}={'='*50}{Style.RESET_ALL}\n")

            # SPF Check
            spf_header = msg.get('Received-SPF', 'Not Available')
            print(f"{Fore.GREEN}SPF:{Style.RESET_ALL} {spf_header}")

            # DKIM Check
            dkim_header = msg.get('DKIM-Signature', 'Not Available')
            print(f"{Fore.GREEN}DKIM:{Style.RESET_ALL} {dkim_header}")

            # DMARC Check
            dmarc_header = msg.get('DMARC-Status', 'Not Available')
            print(f"{Fore.GREEN}DMARC:{Style.RESET_ALL} {dmarc_header}")

            return True

        except Exception as e:
            self.logger.error(f"{Fore.RED}Error printing security headers: {e}{Style.RESET_ALL}")
            return False
