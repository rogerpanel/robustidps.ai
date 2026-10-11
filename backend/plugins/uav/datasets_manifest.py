"""Chapter-6 dataset manifest — single source of truth for the 17 UAV
datasets the framework evaluates against. Drives the React Dataset
Selector dropdowns and the on-demand download buttons.

Tier semantics:
  curated_50mb   pre-loaded demo subset (always available, fast)
  on_demand      can be fetched live (<2 GB; risky on bad wifi)
  reference_only too large to fetch during a defense (>2 GB); URL only
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

Tier = Literal["curated_50mb", "on_demand", "reference_only"]


@dataclass(frozen=True)
class UAVDataset:
    id: str
    name: str
    domain: str
    size_full: str
    tier: Tier
    source_url: str
    citation: str
    relevant_pages: tuple[str, ...]
    demo_subset_path: str | None = None


# Chapter 6 §6.6 — all 17 evaluation datasets.
DATASETS: list[UAVDataset] = [
    # Aerial vision
    UAVDataset("visdrone", "VisDrone-DET", "Aerial detection",
        "~9 GB (261,908 frames)", "reference_only",
        "https://github.com/VisDrone/VisDrone-Dataset",
        "Zhu et al., ECCV 2018; TPAMI 2021",
        ("/uav/perception",)),
    UAVDataset("uavdt", "UAVDT", "Aerial vehicle tracking",
        "~6 GB (80,000 frames)", "reference_only",
        "https://sites.google.com/site/daviddo0323/projects/uavdt",
        "Du et al., ECCV 2018",
        ("/uav/perception",)),
    UAVDataset("auair", "AU-AIR", "Multi-modal aerial",
        "12 GB (32,823 frames + IMU/GPS)", "on_demand",
        "https://bozcani.github.io/auairdataset",
        "Bozcan & Kayacan, ICRA 2020",
        ("/uav/perception", "/uav"),
        demo_subset_path="sample_data/uav/auair_subset.json"),
    UAVDataset("dota", "DOTA v2", "Aerial detection",
        "~30 GB (2,806 images, 188,282 instances)", "reference_only",
        "https://captain-whu.github.io/DOTA/",
        "Xia et al., CVPR 2018",
        ("/uav/perception",)),
    UAVDataset("apricot", "APRICOT", "Adversarial patches in the wild",
        "~4 GB", "reference_only",
        "https://apricot.mitre.org/",
        "MITRE 2020",
        ("/uav/perception",)),
    UAVDataset("drone_vs_bird", "Drone-vs-Bird", "Aerial drone discrimination",
        "~5 GB (107 videos)", "reference_only",
        "https://wosdetc2025.wordpress.com/",
        "Coluccia et al., WOSDETC challenge",
        ("/uav/perception",)),
    # GNSS spoofing
    UAVDataset("texbat", "TEXBAT", "GNSS L1 C/A spoofing IQ",
        "~120 GB (8 scenarios)", "on_demand",
        "https://radionavlab.ae.utexas.edu/datastore/texbat/",
        "Humphreys et al., 2012/2015",
        ("/uav/gnss",),
        demo_subset_path="sample_data/uav/texbat_synthetic.json"),
    UAVDataset("oakbat", "OAKBAT", "GPS L1 + Galileo E1 spoofing",
        "~80 GB (multi-scenario)", "reference_only",
        "https://gps.mae.cornell.edu/oakbat",
        "Bhamidipati et al., 2020",
        ("/uav/gnss",)),
    UAVDataset("fgi_spoofrepo", "FGI-SpoofRepo", "Multi-GNSS spoofing",
        "~40 GB", "reference_only",
        "https://www.maanmittauslaitos.fi/en/research/databases/fgi-spoofrepo",
        "Finnish Geospatial Research Institute, 2024",
        ("/uav/gnss",)),
    # FANET / IoT
    UAVDataset("nature_fanet", "Nature FANET", "Grey-hole FANET telemetry",
        "~200 MB (time series)", "on_demand",
        "https://www.nature.com/articles/s41597-025-00001-1",
        "Nature Scientific Data, 2025",
        ("/uav/swarm",),
        demo_subset_path="sample_data/uav/fanet_subset.csv"),
    UAVDataset("cic_iot_2023", "CIC-IoT-2023", "IoT/IoD intrusion",
        "~13 GB (105 devices, 33 attacks)", "reference_only",
        "https://www.unb.ca/cic/datasets/iotdataset-2023.html",
        "CIC, University of New Brunswick",
        ("/uav/swarm",)),
    UAVDataset("edge_iiot", "Edge-IIoT-Set", "Edge IoT intrusion",
        "~8 GB (2.1M records, 14 attacks)", "reference_only",
        "https://www.kaggle.com/datasets/mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot",
        "Ferrag et al., 2022",
        ("/uav/swarm",)),
    # MAVLink / simulation
    UAVDataset("mavsec", "MAVSec", "MAVLink security mechanisms",
        "~50 MB (benchmark traces)", "on_demand",
        "https://github.com/aniass/MAVSec",
        "Allouch et al., IWCMC 2019",
        ("/uav/mission-plan",),
        demo_subset_path="sample_data/uav/mavsec_traces.json"),
    UAVDataset("airsim", "Microsoft AirSim", "UAV simulator",
        "configurable (~10 GB typical)", "reference_only",
        "https://microsoft.github.io/AirSim/",
        "Shah et al., Field & Service Robotics 2017",
        ("/uav", "/uav/perception")),
    UAVDataset("syndronevision", "SynDroneVision", "Synthetic UAV vision",
        "configurable", "reference_only",
        "https://github.com/syndronevision",
        "2024",
        ("/uav/perception",)),
    UAVDataset("isaid", "iSAID", "Aerial instance segmentation",
        "~50 GB (655,451 instances)", "reference_only",
        "https://captain-whu.github.io/iSAID/",
        "Waqas Zamir et al., CVPRW 2019",
        ("/uav/perception",)),
    UAVDataset("dior", "DIOR", "Aerial detection (remote sensing)",
        "~15 GB (23,463 images, 20 categories)", "reference_only",
        "https://gcheng-nwpu.github.io/",
        "Li et al., ISPRS J. P&RS 2020",
        ("/uav/perception",)),
]


def list_for_page(page: str) -> list[UAVDataset]:
    return [d for d in DATASETS if page in d.relevant_pages]


def get_by_id(dataset_id: str) -> UAVDataset | None:
    return next((d for d in DATASETS if d.id == dataset_id), None)


def _effective_tier(d: UAVDataset) -> str:
    """Promote on_demand to curated_50mb when the local subset file
    is actually on disk — this lets the bootstrap script flip a
    dataset's UI tier without editing the manifest source."""
    if d.demo_subset_path is not None and Path(d.demo_subset_path).exists():
        return "curated_50mb"
    return d.tier


def manifest_payload() -> dict:
    """Serialisable manifest for the React Dataset Selector."""
    return {
        "n_datasets": len(DATASETS),
        "tiers": {
            "curated_50mb": "Pre-loaded demo subset (always available, fast)",
            "on_demand": "Can be fetched live (<2 GB)",
            "reference_only": "Too large to fetch during a defense (>2 GB); URL only",
        },
        "datasets": [
            {
                "id": d.id, "name": d.name, "domain": d.domain,
                "size_full": d.size_full, "tier": _effective_tier(d),
                "declared_tier": d.tier,
                "source_url": d.source_url, "citation": d.citation,
                "relevant_pages": list(d.relevant_pages),
                "demo_subset_available": d.demo_subset_path is not None and Path(d.demo_subset_path).exists(),
            }
            for d in DATASETS
        ],
    }
