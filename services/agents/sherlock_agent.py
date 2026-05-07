import os
from services.agents.agent_server import main

os.environ.setdefault("OSINT_AGENT_TOOL", "sherlock")
os.environ.setdefault("OSINT_AGENT_PORT", os.getenv("OSINT_AGENT_PORT_SHERLOCK", "8112"))

if __name__ == "__main__":
    main()

