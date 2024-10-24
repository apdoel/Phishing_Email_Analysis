from typing import Dict, List, Optional, Set
from colorama import Fore, Style, init
import logging
import re
from email import message
import socket
from dataclasses import dataclass

@dataclass
class EmailIOCs:
    ips: Set[str]
    domains: Set[str]
    urls: Set[str]
    emails: Set[str]
    attachments: Set[str]
    suspicious_headers: List[Dict[str, str]]

class EmailIOCAnalyzer:
    def __init__(self):
        """Initialize the EmailIOCAnalyzer with colorama and logging setup"""
        init(autoreset=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def extract_domains_from_url(self, url: str) -> Optional[str]:
        """Extract domain from URL"""
        try:
            from urllib.parse import urlparse
            return urlparse(url).netloc
        except Exception:
            return None

    def analyze_spf_record(self, spf_header: str) -> Dict[str, str]:
        """Analyze SPF record for suspicious indicators"""
        result = {
            'status': 'Unknown',
            'details': ''
        }
        
        if not spf_header or spf_header == 'Not Available':
            result['status'] = 'Missing'
            result['details'] = 'SPF record not found'
            return result
            
        if 'fail' in spf_header.lower():
            result['status'] = 'Failed'
            result['details'] = 'SPF authentication failed'
        elif 'softfail' in spf_header.lower():
            result['status'] = 'SoftFail'
            result['details'] = 'SPF soft failure - potential spoofing'
        elif 'pass' in spf_header.lower():
            result['status'] = 'Pass'
            result['details'] = 'SPF authentication passed'
            
        return result

    def analyze_dkim_record(self, dkim_header: str) -> Dict[str, str]:
        """Analyze DKIM record for suspicious indicators"""
        result = {
            'status': 'Unknown',
            'details': ''
        }
        
        if not dkim_header or dkim_header == 'Not Available':
            result['status'] = 'Missing'
            result['details'] = 'DKIM signature not found'
            return result
            
        if 'fail' in dkim_header.lower():
            result['status'] = 'Failed'
            result['details'] = 'DKIM verification failed'
        elif 'pass' in dkim_header.lower():
            result['status'] = 'Pass'
            result['details'] = 'DKIM verification passed'
            
        return result

    def analyze_dmarc_record(self, dmarc_header: str) -> Dict[str, str]:
        """Analyze DMARC record for suspicious indicators"""
        result = {
            'status': 'Unknown',
            'details': ''
        }
        
        if not dmarc_header or dmarc_header == 'Not Available':
            result['status'] = 'Missing'
            result['details'] = 'DMARC record not found'
            return result
            
        if 'reject' in dmarc_header.lower():
            result['status'] = 'Reject'
            result['details'] = 'DMARC policy set to reject'
        elif 'quarantine' in dmarc_header.lower():
            result['status'] = 'Quarantine'
            result['details'] = 'DMARC policy set to quarantine'
        elif 'none' in dmarc_header.lower():
            result['status'] = 'None'
            result['details'] = 'DMARC policy set to none'
            
        return result

    def extract_iocs(self, msg: message.EmailMessage) -> EmailIOCs:
        """Extract all IOCs from email message"""
        iocs = EmailIOCs(
            ips=set(),
            domains=set(),
            urls=set(),
            emails=set(),
            attachments=set(),
            suspicious_headers=[]
        )
        
        try:
            # Extract IPs
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            received_headers = msg.get_all('Received', [])
            for header in received_headers:
                iocs.ips.update(re.findall(ip_pattern, header))

            # Extract URLs
            url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
            for part in msg.walk():
                if part.get_content_type() in ['text/plain', 'text/html']:
                    content = part.get_content()
                    found_urls = re.findall(url_pattern, content)
                    iocs.urls.update(found_urls)
                    # Extract domains from URLs
                    for url in found_urls:
                        domain = self.extract_domains_from_url(url)
                        if domain:
                            iocs.domains.add(domain)

            # Extract email addresses
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            for header in ['From', 'To', 'Cc', 'Bcc', 'Reply-To']:
                value = msg.get(header, '')
                if value:
                    iocs.emails.update(re.findall(email_pattern, value))

            # Extract attachments
            for part in msg.walk():
                if part.get_content_maintype() == 'multipart':
                    continue
                if part.get('Content-Disposition') is None:
                    continue
                    
                filename = part.get_filename()
                if filename:
                    iocs.attachments.add(filename)

            # Analyze authentication headers
            spf_result = self.analyze_spf_record(msg.get('Received-SPF', ''))
            if spf_result['status'] in ['Failed', 'SoftFail', 'Missing']:
                iocs.suspicious_headers.append({
                    'header': 'SPF',
                    'status': spf_result['status'],
                    'details': spf_result['details']
                })

            dkim_result = self.analyze_dkim_record(msg.get('DKIM-Signature', ''))
            if dkim_result['status'] in ['Failed', 'Missing']:
                iocs.suspicious_headers.append({
                    'header': 'DKIM',
                    'status': dkim_result['status'],
                    'details': dkim_result['details']
                })

            dmarc_result = self.analyze_dmarc_record(msg.get('DMARC-Status', ''))
            if dmarc_result['status'] in ['None', 'Missing']:
                iocs.suspicious_headers.append({
                    'header': 'DMARC',
                    'status': dmarc_result['status'],
                    'details': dmarc_result['details']
                })

            return iocs

        except Exception as e:
            self.logger.error(f"{Fore.RED}Error extracting IOCs: {e}{Style.RESET_ALL}")
            return iocs

    def print_analysis_results(self, iocs: EmailIOCs) -> None:
        """Print analysis results in a formatted way"""
        print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Email IOCs Analysis Results{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}\n")

        # Print suspicious headers
        if iocs.suspicious_headers:
            print(f"{Fore.RED}Suspicious Authentication Headers:{Style.RESET_ALL}")
            for header in iocs.suspicious_headers:
                print(f"  • {header['header']}: {header['status']}")
                print(f"    Details: {header['details']}")
            print()

        # Print IPs
        if iocs.ips:
            print(f"{Fore.GREEN}Detected IPs:{Style.RESET_ALL}")
            for ip in iocs.ips:
                print(f"  • {ip}")
            print()

        # Print Domains
        if iocs.domains:
            print(f"{Fore.GREEN}Detected Domains:{Style.RESET_ALL}")
            for domain in iocs.domains:
                print(f"  • {domain}")
            print()

        # Print URLs
        if iocs.urls:
            print(f"{Fore.GREEN}Detected URLs:{Style.RESET_ALL}")
            for url in iocs.urls:
                print(f"  • {url}")
            print()

        # Print Email Addresses
        if iocs.emails:
            print(f"{Fore.GREEN}Detected Email Addresses:{Style.RESET_ALL}")
            for email in iocs.emails:
                print(f"  • {email}")
            print()

        # Print Attachments
        if iocs.attachments:
            print(f"{Fore.GREEN}Detected Attachments:{Style.RESET_ALL}")
            for attachment in iocs.attachments:
                print(f"  • {attachment}")
            print()
