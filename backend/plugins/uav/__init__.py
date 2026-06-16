"""UAV / Aerial Defense plugin for RobustIDPS.ai.

Implements chapter 6 of the parent dissertation: the Mission-Completion-Rate
vs J/S framework, the M1-M7 + CyberSecLLM mapping onto airframe / droneport /
cloud tiers, and the certified-robustness operator surface.

Mounted into the FastAPI app via `from plugins.uav import router`.
"""
from plugins.uav.api import router  # noqa: F401
