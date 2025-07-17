import socket
import logging
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class URLAnalyzer:
    def __init__(self):
        self.suspicious_keywords = ['login', 'password', 'account', 'verify', 'secure', 'update', 'bank']
        self.suspicious_tlds = ['.xyz', '.top', '.info', '.loan', '.win']
        self.suspicious_chars = ['-', '_', '@', '%', '#']

    def extract_domain(self, url):
        parsed_url = urlparse(url)
        domain = parsed_url.netloc or parsed_url.path
        return domain.lower()

    def extract_ip(self, url):
        try:
            domain = self.extract_domain(url)
            ip = socket.gethostbyname(domain)
            return ip
        except socket.gaierror:
            logger.warning(f"Could not resolve IP for {url}, skipping IP-based checks")
            return None

    async def analyze_url(self, url, session=None):
        logger.info(f"Analyzing URL {url} with heuristics")
        domain = self.extract_domain(url)
        parsed_url = urlparse(url if url.startswith(('http://', 'https://')) else f"http://{url}")

        # Heuristic checks
        url_length = len(url)
        keyword_count = sum(1 for keyword in self.suspicious_keywords if keyword.lower() in url.lower())
        tld = f".{domain.split('.')[-1]}" if '.' in domain else ''
        is_suspicious_tld = tld in self.suspicious_tlds
        suspicious_char_count = sum(url.count(char) for char in self.suspicious_chars)
        is_ip_address = bool(parsed_url.netloc.replace('.', '').isdigit())

        # Scoring
        malicious_score = (
            (0.3 * (url_length > 60)) +
            (0.3 * keyword_count) +
            (0.2 * is_suspicious_tld) +
            (0.2 * suspicious_char_count) +
            (0.3 * is_ip_address)
        ) * 100

        result = {
            "source": "Heuristic Analysis",
            "malicious": int(malicious_score > 50),
            "suspicious": int(30 <= malicious_score <= 50),
            "harmless": int(malicious_score < 30),
            "undetected": 0,
            "details": {
                "url_length": url_length,
                "keyword_count": keyword_count,
                "suspicious_tld": is_suspicious_tld,
                "suspicious_chars": suspicious_char_count,
                "is_ip_address": is_ip_address
            }
        }
        logger.info(f"Heuristic results for {url}: {result}")
        return result
