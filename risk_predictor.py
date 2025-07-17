import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RiskPredictor:
    def __init__(self):
        self.suspicious_keywords = ['login', 'password', 'account', 'verify']

    def extract_features(self, url, osint_data, analysis_data):
        features = {
            "url_length": len(url),
            "suspicious_keywords": sum(1 for keyword in self.suspicious_keywords if keyword.lower() in url.lower()),
            "domain_age": 0,
            "blocklist_malicious": 0,
            "heuristic_score": 0
        }
        if "creation_date" in osint_data and osint_data["creation_date"] != "Unknown":
            try:
                creation_date = datetime.strptime(osint_data["creation_date"], "%Y-%m-%d")
                features["domain_age"] = (datetime.now() - creation_date).days
            except Exception as e:
                logger.error(f"Error calculating domain age: {str(e)}")
        if "malicious" in osint_data:
            features["blocklist_malicious"] = 1 if osint_data["malicious"] else 0
        if "details" in analysis_data:
            features["heuristic_score"] = (
                analysis_data["details"]["keyword_count"] * 0.3 +
                analysis_data["details"]["suspicious_tld"] * 0.2 +
                analysis_data["details"]["suspicious_chars"] * 0.2 +
                analysis_data["details"]["is_ip_address"] * 0.3
            ) * 100
        logger.info(f"Extracted features for {url}: {features}")
        return features

    async def predict_risk(self, url, osint_data, analysis_data):
        features = self.extract_features(url, osint_data, analysis_data)
        risk_score = (
            (0.3 * (features["url_length"] > 60)) +
            (0.3 * features["suspicious_keywords"]) +
            (0.3 * features["blocklist_malicious"]) +
            (0.2 * (features["heuristic_score"] > 50)) -
            (0.2 * (features["domain_age"] > 365))
        )
        risk_probability = max(0, min(100, risk_score * 100))
        risk_level = "High" if risk_probability >= 50 else "Medium" if risk_probability >= 30 else "Low"
        logger.info(f"Risk prediction for {url}: {risk_level} ({risk_probability}%)")
        return {"risk_level": risk_level, "risk_probability": risk_probability}
