import asyncio
from url_analyzer import URLAnalyzer
from osint_checker import OSINTChecker
from risk_predictor import RiskPredictor
from user_interface import UserInterface
from educational_content import EducationalContent
from agent import URLAgent

async def main():
    url_analyzer = URLAnalyzer()
    osint_checker = OSINTChecker()
    risk_predictor = RiskPredictor()
    user_interface = UserInterface()
    educational_content = EducationalContent()
    
    agent = URLAgent(
        url_analyzer,
        osint_checker,
        risk_predictor,
        user_interface,
        educational_content
    )

    while True:
        url = input("Enter a URL to check (or 'quit' to exit): ").strip()
        if url.lower() == 'quit':
            break
        await agent.interact(url)

if __name__ == "__main__":
    asyncio.run(main())
