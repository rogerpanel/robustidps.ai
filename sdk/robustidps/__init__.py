"""
RobustIDPS Python SDK — programmatic access to the RobustIDPS.AI platform.

Usage:
    from robustidps import Client

    client = Client("https://robustidps.example.com")
    client.login("user@example.com", "password")

    # Upload and predict
    result = client.predict("traffic.csv")
    print(result["n_threats"], "threats detected")

    # Red team attack
    arena = client.redteam("traffic.csv", attacks=["fgsm", "pgd"], epsilon=0.1)
    print(arena["robustness_score"])

    # Ablation study
    ablation = client.ablation("traffic.csv", mode="single")
    print(ablation["branch_impact"])
"""

__version__ = "0.1.0"

from robustidps.client import Client

__all__ = ["Client", "__version__"]
