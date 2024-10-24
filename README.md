Here’s a README file for your Email Phishing Detection Tool that you can upload to GitHub:

---

# Email Phishing Detection Tool

This tool helps SOC (Security Operations Center) analysts analyze email headers and attachments for potential phishing attacks. It automates the process of extracting important information from emails, such as IP addresses, URLs, and attachments, and provides reputation checks using external APIs like VirusTotal and AbuseIPDB.

## Features

- **Email Header Analysis**: Extracts important email headers (From, To, Subject, Date) and validates SPF, DKIM, and DMARC records.
- **URL, IP, and Attachment Reputation**: Scans URLs, IP addresses, and attachments found in emails and checks their reputation against VirusTotal and AbuseIPDB.
- **Indicators of Compromise (IOC) Extraction**: Automatically extracts key IOCs such as IP addresses, domains, URLs, email addresses, and suspicious attachments from emails.
- **Interactive Command-Line Interface**: Provides a menu-based interface for SOC analysts to analyze email files easily.

## Prerequisites

- Python 3.6 or above
- `colorama` for colored terminal output
- `requests` for making API requests

You can install the required Python dependencies by running:

```bash
pip install -r requirements.txt
```

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/email-phishing-detection-tool.git
   ```
2. Navigate to the project directory:
   ```bash
   cd email-phishing-detection-tool
   ```
3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Ensure you have your VirusTotal and AbuseIPDB API keys. Add them to the tool by running the program and entering the keys when prompted.
   
2. To analyze an email:
   ```bash
   python main.py
   ```

3. You will be prompted to provide the path to an `.eml` file (email file) for analysis. The tool provides a menu for:
   - Printing important headers.
   - Printing security headers (SPF, DKIM, DMARC).
   - Analyzing URLs, IPs, and attachments.
   - Extracting Indicators of Compromise (IOCs).

## Configuration

API keys are stored in a `config.json` file within the project directory. If you do not provide API keys when first prompted, you can manually edit or add them to this file:

```json
{
  "vt_api_key": "your_virustotal_api_key",
  "abuse_api_key": "your_abuseipdb_api_key"
}
```

## File Structure

- `main.py`: Entry point of the application, manages user interactions and analysis options.
- `email_header_analyzer.py`: Handles email header analysis.
- `email_ioc_analyzer.py`: Extracts and prints IOCs from email content.
- `url_ip_and_attachment_reputation_analysis.py`: Analyzes URLs, IPs, and attachments for malicious reputation.
- `config.json`: Stores API keys for external services (VirusTotal and AbuseIPDB).

## Future Enhancements

- Integration with more APIs for a broader reputation check.
- Machine learning model to improve phishing detection accuracy.
- Improved attachment analysis to support additional file types.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Contributing

Contributions are welcome! Please fork the repository and create a pull request to propose changes.

---

This README provides all the necessary information for anyone to clone, run, and contribute to your project.
