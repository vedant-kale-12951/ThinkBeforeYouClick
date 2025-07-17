import whois
import asyncio
import logging
import os
import pickle
from datetime import datetime
from blocklist import BlocklistChecker

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class OSINTChecker:
    def __init__(self, cache_file="whois_cache.pkl"):
        self.cache_file = cache_file
        self.blocklist_checker = BlocklistChecker()
        self.whois_cache = self.load_cache()

    def load_cache(self):
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, "rb") as f:
                    return pickle.load(f)
            return {}
        except Exception as e:
            logger.error(f"Error loading WHOIS cache: {str(e)}")
            return {}

    def save_cache(self):
        try:
            with open(self.cache_file, "wb") as f:
                pickle.dump(self.whois_cache, f)
            logger.info(f"Saved WHOIS cache to {self.cache_file}")
        except Exception as e:
            logger.error(f"Error saving WHOIS cache: {str(e)}")

    def _normalize_date(self, date):
        """Convert WHOIS date to string in YYYY-MM-DD format."""
        if isinstance(date, list):
            date = date[0] if date else None
        if isinstance(date, datetime):
            return date.strftime("%Y-%m-%d")
        return str(date) if date else "Unknown"

    async def get_whois_info(self, domain):
        if domain in self.whois_cache:
            logger.info(f"WHOIS cache hit for {domain}")
            return self.whois_cache[domain]
        try:
            logger.info(f"Fetching WHOIS for {domain}")
            w = whois.whois(domain)
            result = {
                "registrar": w.registrar or "Unknown",
                "creation_date": self._normalize_date(w.creation_date),
                "expiration_date": self._normalize_date(w.expiration_date)
            }
            self.whois_cache[domain] = result
            self.save_cache()
            return result
        except Exception as e:
            logger.error(f"WHOIS error for {domain}: {str(e)}")
            return {"whois_error": str(e)}

    async def check_domain_reputation(self, domain, ip, session=None):
        whois_task = self.get_whois_info(domain)
        blocklist_result = self.blocklist_checker.check_domain(domain)
        whois_result = await whois_task
        osint_data = {**whois_result, **blocklist_result}
        logger.info(f"Aggregated OSINT results for {domain}: {osint_data}")
        return osint_data
