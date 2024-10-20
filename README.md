This GitHub repository contains a **Phishing Email Analysis Tool** designed to help SOC analysts detect potential phishing emails by analyzing various components such as email headers, embedded links, and attachments.

### Key Features:
- **Header Analysis**: Checks for suspicious indicators such as mismatched 'From' and 'Return-Path' headers, suspicious 'Reply-To' addresses, and authentication results (SPF, DKIM, DMARC).
- **Link Analysis**: Extracts and analyzes all URLs found in the email body. The tool verifies whether the links are malicious using the VirusTotal API and flags any non-HTTPS links.
- **Attachment Inspection**: Lists any attachments found in the email, highlighting potential malicious files.
- **SPF and DMARC Querying**: Performs DNS lookups to verify SPF and DMARC records, ensuring the email originates from authorized sources.
- **User-Friendly Output**: Provides clear, color-coded summaries of suspicious indicators, link reputations, and attachment details, aiding analysts in making informed decisions quickly.

### How This Tool Helps SOC Analysts:
This tool automates key aspects of phishing detection, reducing the manual effort needed to investigate suspicious emails. By flagging phishing indicators and providing detailed analysis reports, it empowers SOC analysts to efficiently assess potential threats and respond accordingly.
