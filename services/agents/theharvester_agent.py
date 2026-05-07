import os
from services.agents.agent_server import main

os.environ.setdefault("OSINT_AGENT_TOOL", "theharvester")
os.environ.setdefault("OSINT_AGENT_PORT", os.getenv("OSINT_AGENT_PORT_THEHARVESTER", "8116"))

if __name__ == "__main__":
    main()

