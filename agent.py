import json
import os
import logging
from urllib.parse import urlparse
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class URLAgent:
    def __init__(self, url_analyzer, osint_checker, risk_predictor, user_interface, educational_content, memory_file="url_memory.json"):
        self.url_analyzer = url_analyzer
        self.osint_checker = osint_checker
        self.risk_predictor = risk_predictor
        self.user_interface = user_interface
        self.educational_content = educational_content
        self.memory_file = memory_file
        self.memory = self.load_memory()

    def load_memory(self):
        """Load URL analysis memory from JSON file."""
        try:
            if os.path.exists(self.memory_file):
                with open(self.memory_file, "r") as f:
                    return json.load(f)
            return {}
        except Exception as e:
            logger.error(f"Error loading memory: {str(e)}")
            return {}

    def save_memory(self, url, analysis, osint, risk, reasoning, phishing_example):
        """Save URL analysis to memory."""
        try:
            domain = urlparse(url).netloc.lower() or url
            self.memory[domain] = {
                "url": url,
                "analysis": analysis,
                "osint": osint,
                "risk": risk,
                "reasoning": reasoning,
                "phishing_example": phishing_example,
                "timestamp": datetime.now().isoformat()
            }
            with open(self.memory_file, "w") as f:
                json.dump(self.memory, f, indent=2)
            logger.info(f"Saved analysis for {url} to memory")
        except Exception as e:
            logger.error(f"Error saving memory: {str(e)}")

    async def analyze_url(self, url):
        """Analyze a URL with agentic reasoning."""
        domain = self.url_analyzer.extract_domain(url)
        ip = self.url_analyzer.extract_ip(url)

        # Check memory first
        if domain in self.memory:
            logger.info(f"Memory hit for {domain}")
            cached = self.memory[domain]
            # Regenerate reasoning if missing
            if "reasoning" not in cached:
                cached["reasoning"] = self._reason(url, cached["analysis"], cached["osint"], cached["risk"])
            # Regenerate phishing_example if missing
            if "phishing_example" not in cached:
                cached["phishing_example"] = await self.educational_content.generate_phishing_example()
            if "reasoning" not in cached or "phishing_example" not in cached:
                self.save_memory(
                    url,
                    cached["analysis"],
                    cached["osint"],
                    cached["risk"],
                    cached.get("reasoning", ["No reasoning available"]),
                    cached["phishing_example"]
                )
            return cached

        # Perform analysis
        analysis = await self.url_analyzer.analyze_url(url)
        osint = await self.osint_checker.check_domain_reputation(domain, ip)
        risk = await self.risk_predictor.predict_risk(url, osint, analysis)

        # Reason about the results
        reasoning = self._reason(url, analysis, osint, risk)
        phishing_example = await self.educational_content.generate_phishing_example()

        # Save to memory
        self.save_memory(url, analysis, osint, risk, reasoning, phishing_example)

        # Update blocklist if risky
        if risk["risk_level"] in ["High", "Medium"] or osint.get("malicious", False):
            self.osint_checker.blocklist_checker.add_to_blocklist(domain)

        return {
            "analysis": analysis,
            "osint": osint,
            "risk": risk,
            "reasoning": reasoning,
            "phishing_example": phishing_example
        }

    def _reason(self, url, analysis, osint, risk):
        """Generate reasoning based on analysis results."""
        reasons = []
        if osint.get("malicious", False):
            reasons.append(f"{url} is listed in the blocklist, indicating known malicious activity.")
        if analysis["details"]["url_length"] > 60:
            reasons.append(f"The URL is unusually long ({analysis['details']['url_length']} characters), which is common in phishing URLs.")
        if analysis["details"]["keyword_count"] > 0:
            reasons.append(f"The URL contains {analysis['details']['keyword_count']} suspicious keywords (e.g., 'login', 'verify'), often used in phishing.")
        if analysis["details"]["suspicious_tld"]:
            reasons.append(f"The top-level domain is suspicious (e.g., .xyz, .top), which is often associated with malicious sites.")
        if analysis["details"]["is_ip_address"]:
            reasons.append(f"The URL uses an IP address instead of a domain, a common tactic in malicious links.")
        if osint.get("creation_date", "Unknown") != "Unknown":
            try:
                creation_date = datetime.strptime(osint["creation_date"], "%Y-%m-%d")
                age_days = (datetime.now() - creation_date).days
                if age_days < 365:
                    reasons.append(f"The domain is very new ({age_days} days old), which is a red flag for potential phishing.")
                else:
                    reasons.append(f"The domain is well-established ({age_days} days old), increasing its trustworthiness.")
            except:
                pass
        if not reasons:
            reasons.append(f"No significant red flags detected for {url}.")
        return reasons

    async def interact(self, url):
        """Interact with the user and analyze the URL."""
        if await self.user_interface.prompt_user(url):
            result = await self.analyze_url(url)
            # Display reasoning
            print("\nAgent Reasoning:")
            for reason in result.get("reasoning", ["No reasoning available due to cache error"]):
                print(f"- {reason}")
            # Interactive follow-up for risky URLs
            if result["risk"]["risk_level"] in ["High", "Medium"] or result["osint"].get("malicious", False):
                print("\n⚠️ This URL appears suspicious. Additional context could help refine the analysis.")
                response = input("Did you receive this link in an email or message? (yes/no): ").lower()
                if response == "yes":
                    result["risk"]["risk_probability"] += 20
                    result["risk"]["risk_level"] = "High" if result["risk"]["risk_probability"] >= 50 else "Medium"
                    print("⚠️ Links received in unsolicited emails/messages are often phishing attempts. Exercise extreme caution.")
            await self.user_interface.display_results(
                url,
                result["analysis"],
                result["osint"],
                result["risk"],
                result.get("phishing_example", {"error": "Phishing example not available"})
            )
