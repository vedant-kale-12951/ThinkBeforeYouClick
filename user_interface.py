import asyncio
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class UserInterface:
    def _format_date(self, date_str):
        """Format date string for display."""
        if isinstance(date_str, str) and date_str != "Unknown":
            return date_str
        return "Unknown"

    def _get_url_status(self, analysis, osint, risk):
        """Determine if the URL is Safe, Suspicious, or Malicious."""
        if osint.get("malicious", False) or risk["risk_level"] == "High":
            return "Malicious"
        elif risk["risk_level"] == "Medium":
            return "Suspicious"
        return "Safe"

    async def prompt_user(self, url):
        print(f"\nFound a link: {url}")
        response = input("Want me to investigate this link before you open it? (yes/no): ").lower()
        return response == "yes"

    async def generate_summary(self, url, analysis, osint, risk, session=None):
        logger.info(f"Generating static summary for {url}")
        if risk['risk_level'] == 'High' or osint.get('malicious', False):
            return f"⚠️ Warning: {url} appears risky. It may be flagged in blocklists or has suspicious characteristics."
        elif risk['risk_level'] == 'Medium':
            return f"⚠️ Caution: {url} has some suspicious traits. Verify before clicking."
        return f"{url} appears safe based on analysis, but always exercise caution."

    async def display_results(self, url, analysis, osint, risk, phishing_example, session=None):
        print("\n--- Before You Click Analysis ---")
        print(f"Link: {url}")
        print(f"URL Status: {self._get_url_status(analysis, osint, risk)}")
        
        summary = await self.generate_summary(url, analysis, osint, risk)
        print("\nSummary:")
        print(summary)

        print("\nDetailed Results:")
        if "error" in analysis:
            print(f"{analysis['source']} Analysis: Error - {analysis['error']}")
        else:
            print(f"{analysis['source']}:")
            print(f"  Malicious: {analysis['malicious']} {'engine' if analysis['malicious'] == 1 else 'engines'} flagged")
            print(f"  Suspicious: {analysis['suspicious']} {'engine' if analysis['suspicious'] == 1 else 'engines'} flagged")
            print(f"  Harmless: {analysis['harmless']} {'engine' if analysis['harmless'] == 1 else 'engines'} flagged")
            print(f"  Details: {analysis['details']}")

        print("\nOSINT Results:")
        if isinstance(osint, dict) and osint:
            if "registrar" in osint:
                print(f"  WHOIS:")
                print(f"    Registrar: {osint['registrar']}")
                print(f"    Creation Date: {self._format_date(osint['creation_date'])}")
                print(f"    Expiration Date: {self._format_date(osint['expiration_date'])}")
            if "whois_error" in osint:
                print(f"  WHOIS: Error - {osint['whois_error']}")
            if "source" in osint:
                print(f"  {osint['source']}:")
                print(f"    Malicious: {osint['malicious']}")
                print(f"    Reason: {osint['reason']}")
        else:
            print(f"  OSINT Check: Error - {osint if isinstance(osint, str) else 'No OSINT data available'}")

        print(f"\nRisk Prediction: {risk['risk_level']} (Probability: {risk['risk_probability']:.2f}%)")

        if "error" in phishing_example:
            print(f"\nEducational Content: Error - {phishing_example['error']}")
        else:
            print(f"\nEducational Content (Example Phishing Email):")
            print(phishing_example["phishing_example"])
