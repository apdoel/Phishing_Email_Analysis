import requests
import json
import hashlib
import os
from typing import Dict, List, Optional, Tuple
from colorama import Fore, Style, init
import logging
from urllib.parse import urlparse
import re
import time

class ReputationAnalyzer:
    def __init__(self, vt_api_key: str = None, abuse_api_key: str = None, cache_dir: str = "cache"):
        """
        Initialize the ReputationAnalyzer with API keys and cache setup
        
        Args:
            vt_api_key (str): VirusTotal API key
            abuse_api_key (str): AbuseIPDB API key
            cache_dir (str): Directory to store cache files
        """
        init(autoreset=True)
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        self.vt_api_key = vt_api_key
        self.abuse_api_key = abuse_api_key
        self.cache_dir = cache_dir
        
        # Create cache directory if it doesn't exist
        if not os.path.exists(cache_dir):
            os.makedirs(cache_dir)
            
        # Cache timing (24 hours)
        self.cache_duration = 86400

    def extract_urls_from_email(self, msg: 'email.message.EmailMessage') -> List[str]:
        """
        Extract URLs from email body
        
        Args:
            msg: Email message object
            
        Returns:
            List[str]: List of unique URLs found
        """
        try:
            urls = set()
            
            # URL regex pattern
            url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
            
            # Check all parts of the email
            for part in msg.walk():
                if part.get_content_type() in ['text/plain', 'text/html']:
                    content = part.get_content()
                    found_urls = re.findall(url_pattern, content)
                    urls.update(found_urls)
            
            return list(urls)
        except Exception as e:
            self.logger.error(f"{Fore.RED}Error extracting URLs: {e}{Style.RESET_ALL}")
            return []

    def get_received_ips(self, msg: 'email.message.EmailMessage') -> List[str]:
        """
        Extract all IPs from Received headers
        
        Args:
            msg: Email message object
            
        Returns:
            List[str]: List of unique IPs found
        """
        try:
            ips = set()
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            
            received_headers = msg.get_all('Received', [])
            for header in received_headers:
                found_ips = re.findall(ip_pattern, header)
                ips.update(found_ips)
            
            return list(ips)
        except Exception as e:
            self.logger.error(f"{Fore.RED}Error extracting IPs: {e}{Style.RESET_ALL}")
            return []

    def calculate_file_hash(self, file_path: str) -> Optional[str]:
        """
        Calculate SHA-256 hash of a file
        
        Args:
            file_path (str): Path to the file
            
        Returns:
            Optional[str]: SHA-256 hash or None if error occurs
        """
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            self.logger.error(f"{Fore.RED}Error calculating file hash: {e}{Style.RESET_ALL}")
            return None

    def check_cache(self, cache_key: str) -> Optional[Dict]:
        """
        Check if result exists in cache and is still valid
        
        Args:
            cache_key (str): Cache key to check
            
        Returns:
            Optional[Dict]: Cached data if valid, None otherwise
        """
        cache_file = os.path.join(self.cache_dir, f"{cache_key}.json")
        try:
            if os.path.exists(cache_file):
                with open(cache_file, 'r') as f:
                    cached_data = json.load(f)
                    if time.time() - cached_data['timestamp'] < self.cache_duration:
                        return cached_data['data']
            return None
        except Exception as e:
            self.logger.error(f"{Fore.RED}Error checking cache: {e}{Style.RESET_ALL}")
            return None

    def save_to_cache(self, cache_key: str, data: Dict) -> None:
        """
        Save result to cache
        
        Args:
            cache_key (str): Cache key
            data (Dict): Data to cache
        """
        cache_file = os.path.join(self.cache_dir, f"{cache_key}.json")
        try:
            cache_data = {
                'timestamp': time.time(),
                'data': data
            }
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f)
        except Exception as e:
            self.logger.error(f"{Fore.RED}Error saving to cache: {e}{Style.RESET_ALL}")

    def check_url_reputation(self, url: str) -> Optional[Dict]:
        """
        Check URL reputation using VirusTotal API
        
        Args:
            url (str): URL to check
            
        Returns:
            Optional[Dict]: Reputation data or None if error occurs
        """
        if not self.vt_api_key:
            self.logger.error(f"{Fore.RED}VirusTotal API key not provided{Style.RESET_ALL}")
            return None

        try:
            # Check cache first
            cache_key = f"url_{hashlib.md5(url.encode()).hexdigest()}"
            cached_result = self.check_cache(cache_key)
            if cached_result:
                return cached_result

            # Make API request
            headers = {
                'x-apikey': self.vt_api_key
            }
            response = requests.get(
                f'https://www.virustotal.com/vtapi/v2/url/report',
                params={'apikey': self.vt_api_key, 'resource': url},
                headers=headers
            )
            response.raise_for_status()
            result = response.json()
            
            # Save to cache
            self.save_to_cache(cache_key, result)
            
            return result
        except Exception as e:
            self.logger.error(f"{Fore.RED}Error checking URL reputation: {e}{Style.RESET_ALL}")
            return None

    def check_ip_reputation(self, ip: str) -> Optional[Dict]:
        """
        Check IP reputation using AbuseIPDB API
        
        Args:
            ip (str): IP address to check
            
        Returns:
            Optional[Dict]: Reputation data or None if error occurs
        """
        if not self.abuse_api_key:
            self.logger.error(f"{Fore.RED}AbuseIPDB API key not provided{Style.RESET_ALL}")
            return None

        try:
            # Check cache first
            cache_key = f"ip_{ip}"
            cached_result = self.check_cache(cache_key)
            if cached_result:
                return cached_result

            # Make API request
            headers = {
                'Accept': 'application/json',
                'Key': self.abuse_api_key
            }
            response = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                params={'ipAddress': ip, 'maxAgeInDays': '90'},
                headers=headers
            )
            response.raise_for_status()
            result = response.json()
            
            # Save to cache
            self.save_to_cache(cache_key, result)
            
            return result
        except Exception as e:
            self.logger.error(f"{Fore.RED}Error checking IP reputation: {e}{Style.RESET_ALL}")
            return None

    def check_file_reputation(self, file_path: str) -> Optional[Dict]:
        """
        Check file reputation using VirusTotal API
        
        Args:
            file_path (str): Path to the file
            
        Returns:
            Optional[Dict]: Reputation data or None if error occurs
        """
        if not self.vt_api_key:
            self.logger.error(f"{Fore.RED}VirusTotal API key not provided{Style.RESET_ALL}")
            return None

        try:
            file_hash = self.calculate_file_hash(file_path)
            if not file_hash:
                return None

            # Check cache first
            cache_key = f"file_{file_hash}"
            cached_result = self.check_cache(cache_key)
            if cached_result:
                return cached_result

            # Make API request
            headers = {
                'x-apikey': self.vt_api_key
            }
            response = requests.get(
                f'https://www.virustotal.com/vtapi/v2/file/report',
                params={'apikey': self.vt_api_key, 'resource': file_hash},
                headers=headers
            )
            response.raise_for_status()
            result = response.json()
            
            # Save to cache
            self.save_to_cache(cache_key, result)
            
            return result
        except Exception as e:
            self.logger.error(f"{Fore.RED}Error checking file reputation: {e}{Style.RESET_ALL}")
            return None

    def analyze_email_content(self, msg: 'email.message.EmailMessage', attachments_dir: str = None) -> None:
        """
        Analyze all aspects of email content (URLs, IPs, attachments)
        
        Args:
            msg: Email message object
            attachments_dir (str): Directory to save attachments for analysis
        """
        print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Email Content Analysis{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}\n")

        # Analyze URLs
        urls = self.extract_urls_from_email(msg)
        if urls:
            print(f"{Fore.GREEN}Found URLs:{Style.RESET_ALL}")
            for url in urls:
                result = self.check_url_reputation(url)
                if result:
                    positives = result.get('positives', 0)
                    total = result.get('total', 0)
                    print(f"  {url}")
                    print(f"    Detection ratio: {positives}/{total}")
                    if positives > 0:
                        print(f"    {Fore.RED}Warning: URL has been flagged as malicious{Style.RESET_ALL}")

        # Analyze IPs
        ips = self.get_received_ips(msg)
        if ips:
            print(f"\n{Fore.GREEN}Received IPs:{Style.RESET_ALL}")
            for ip in ips:
                result = self.check_ip_reputation(ip)
                if result and 'data' in result:
                    data = result['data']
                    confidence = data.get('abuseConfidenceScore', 0)
                    print(f"  {ip}")
                    print(f"    Abuse confidence score: {confidence}%")
                    if confidence > 50:
                        print(f"    {Fore.RED}Warning: IP has high abuse confidence score{Style.RESET_ALL}")

        # Analyze attachments
        if attachments_dir:
            print(f"\n{Fore.GREEN}Attachments:{Style.RESET_ALL}")
            for part in msg.walk():
                if part.get_content_maintype() == 'multipart':
                    continue
                if part.get('Content-Disposition') is None:
                    continue

                filename = part.get_filename()
                if filename:
                    filepath = os.path.join(attachments_dir, filename)
                    with open(filepath, 'wb') as f:
                        f.write(part.get_payload(decode=True))
                    
                    result = self.check_file_reputation(filepath)
                    if result:
                        positives = result.get('positives', 0)
                        total = result.get('total', 0)
                        print(f"  {filename}")
                        print(f"    Detection ratio: {positives}/{total}")
                        if positives > 0:
                            print(f"    {Fore.RED}Warning: File has been flagged as malicious{Style.RESET_ALL}")
