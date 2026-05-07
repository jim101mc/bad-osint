import os
from services.agents.agent_server import main

os.environ.setdefault("OSINT_AGENT_TOOL", "social-analyzer")
os.environ.setdefault("OSINT_AGENT_PORT", os.getenv("OSINT_AGENT_PORT_SOCIAL_ANALYZER", "8113"))

if __name__ == "__main__":
    main()

