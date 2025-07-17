import logging
import os
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BlocklistChecker:
    def __init__(self, blocklist_file="blocklist.txt"):
        self.blocklist_file = blocklist_file
        self.domains = self.load_blocklist()

    def load_blocklist(self):
        """Load a local blocklist of known malicious domains."""
        try:
            if not os.path.exists(self.blocklist_file):
                logger.warning(f"Blocklist file {self.blocklist_file} not found, creating empty one")
                with open(self.blocklist_file, "w") as f:
                    f.write("# Sample blocklist\nphish.example.com\nmalicious.com")
            with open(self.blocklist_file, "r") as f:
                domains = {line.strip().lower() for line in f if line.strip() and not line.startswith("#")}
            logger.info(f"Loaded {len(domains)} domains from blocklist")
            return domains
        except Exception as e:
            logger.error(f"Error loading blocklist: {str(e)}")
            return set()

    def add_to_blocklist(self, domain):
        """Add a domain to the blocklist."""
        try:
            domain = domain.lower()
            if domain not in self.domains:
                with open(self.blocklist_file, "a") as f:
                    f.write(f"\n{domain}")
                self.domains.add(domain)
                logger.info(f"Added {domain} to blocklist")
        except Exception as e:
            logger.error(f"Error adding {domain} to blocklist: {str(e)}")

    def check_domain(self, url):
        """Check if the domain is in the blocklist."""
        domain = urlparse(url).netloc.lower()
        if not domain:
            domain = urlparse("http://" + url).netloc.lower()
        is_malicious = domain in self.domains
        logger.info(f"Blocklist check for {domain}: {'Malicious' if is_malicious else 'Clean'}")
        return {
            "source": "Local Blocklist",
            "malicious": is_malicious,
            "reason": "Domain found in blocklist" if is_malicious else "Domain not in blocklist"
        }
