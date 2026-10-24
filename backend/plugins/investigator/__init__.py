"""SOC Investigator: an LLM agent that investigates security incidents.

The core (missions, evidence, tools, agent, scorer) has no web-framework
dependency, so it runs standalone as a competition harness via cli.py.
api.py mounts it into the FastAPI app; import it from there, not here.
"""
