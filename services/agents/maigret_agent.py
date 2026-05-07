import os
from services.agents.agent_server import main

os.environ.setdefault("OSINT_AGENT_TOOL", "maigret")
os.environ.setdefault("OSINT_AGENT_PORT", os.getenv("OSINT_AGENT_PORT_MAIGRET", "8114"))

if __name__ == "__main__":
    main()

