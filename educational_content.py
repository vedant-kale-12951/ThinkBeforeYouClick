import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EducationalContent:
    async def generate_phishing_example(self, session=None):
        logger.info("Returning static phishing example")
        return {
            "phishing_example": (
                "Subject: Urgent Account Verification\n"
                "Dear User,\n"
                "Your account requires immediate verification. Click http://suspicious.com/verify to update your details, or your account will be suspended.\n"
                "Best,\nFake Support Team"
            )
        }
