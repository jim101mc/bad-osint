import os
from services.agents.agent_server import main

os.environ.setdefault("OSINT_AGENT_TOOL", "holehe")
os.environ.setdefault("OSINT_AGENT_PORT", os.getenv("OSINT_AGENT_PORT_HOLEHE", "8111"))

if __name__ == "__main__":
    main()

