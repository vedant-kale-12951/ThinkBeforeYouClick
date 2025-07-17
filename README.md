# Before You Click - AI-Powered URL Safety Validator

**Before You Click** is an offline, AI-powered tool designed to analyze URLs for potential phishing or malicious activity. It uses heuristic analysis, WHOIS data, a local blocklist, and an agentic AI to classify URLs as **Safe**, **Suspicious**, or **Malicious**, providing detailed reasoning and educational content to help users make informed decisions about clicking links.

## Features
- **Heuristic Analysis**: Evaluates URLs based on length, suspicious keywords, TLDs, and IP addresses.
- **WHOIS Lookup**: Retrieves domain registration details (registrar, creation date, expiration date) using `python-whois`.
- **Local Blocklist**: Checks URLs against a local blocklist of known malicious domains.
- **Agentic AI**: 
  - Combines analysis results for intelligent reasoning.
  - Stores analysis in a local JSON memory (`url_memory.json`) for quick retrieval.
  - Dynamically updates the blocklist for suspicious/malicious domains.
  - Interactively asks follow-up questions for risky URLs to refine risk assessment.
- **Risk Prediction**: Assigns a risk level (Low, Medium, High) with a probability score.
- **URL Status**: Clearly labels URLs as Safe, Suspicious, or Malicious.
- **Educational Content**: Provides a static phishing email example to educate users.
- **API-Free**: Operates entirely offline, avoiding API rate limits or external dependencies.

## Installation
### Prerequisites
- **Operating System**: Tested on Kali Linux.
- **Python**: Python 3.8+ (Python 3.13 used in development).
- **Dependencies**: `python-whois` for WHOIS lookups.

### Setup
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-username/before-you-click.git
   cd before-you-click
   ```

2. **Create a Virtual Environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install python-whois
   ```

4. **(Optional) Enhance Blocklist**:
   Download a larger blocklist for better malicious URL detection:
   ```bash
   curl -o blocklist.txt https://openphish.com/feed.txt
   ```

## Usage
1. **Run the Program**:
   ```bash
   python3 main.py
   ```

2. **Enter a URL**:
   - Input a URL (e.g., `www.google.com`) or type `quit` to exit.
   - Choose `yes` to analyze the URL when prompted.

3. **Example Output**:
   ```
   Enter a URL to check (or 'quit' to exit): www.google.com
   Found a link: www.google.com
   Want me to investigate this link before you open it? (yes/no): yes

   Agent Reasoning:
   - The domain is well-established (10365 days old), increasing its trustworthiness.

   --- Before You Click Analysis ---
   Link: www.google.com
   URL Status: Safe

   Summary:
   www.google.com appears safe based on analysis, but always exercise caution.

   Detailed Results:
   Heuristic Analysis:
     Malicious: 0 engines flagged
     Suspicious: 0 engines flagged
     Harmless: 1 engine flagged
     Details: {'url_length': 14, 'keyword_count': 0, 'suspicious_tld': False, 'suspicious_chars': 0, 'is_ip_address': False}

   OSINT Results:
     WHOIS:
       Registrar: MarkMonitor, Inc.
       Creation Date: 1997-09-15
       Expiration Date: 2028-09-14
     Local Blocklist:
       Malicious: False
       Reason: Domain not in blocklist

   Risk Prediction: Low (Probability: 0.00%)

   Educational Content (Example Phishing Email):
   Subject: Urgent Account Verification
   Dear User,
   Your account requires immediate verification. Click http://suspicious.com/verify to update your details, or your account will be suspended.
   Best,
   Fake Support Team
   ```

4. **Testing Suspicious/Malicious URLs**:
   - Try `http://login.verify-secure.xyz` (Suspicious) or `phish.example.com` (Malicious, if in `blocklist.txt`).
   - For suspicious URLs, the agent may ask:
     ```
     ⚠️ This URL appears suspicious. Additional context could help refine the analysis.
     Did you receive this link in an email or message? (yes/no):
     ```
