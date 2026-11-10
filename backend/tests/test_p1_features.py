"""
P1 — Feature Extraction
========================
Verify feature lists and extraction logic.
"""

import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from features import (
    CIC_IOT_2023_FEATURES,
    CICIDS2018_FEATURES_FULL,
    CICIDS2018_FEATURES_SHORT,
    UNSW_NB15_FEATURES,
)


class TestFeatureLists:
    def test_cic_iot_2023_not_empty(self):
        assert len(CIC_IOT_2023_FEATURES) > 0

    def test_cic_iot_2023_no_duplicates(self):
        assert len(CIC_IOT_2023_FEATURES) == len(set(CIC_IOT_2023_FEATURES))

    def test_cicids2018_full_not_empty(self):
        assert len(CICIDS2018_FEATURES_FULL) > 0

    def test_cicids2018_full_no_duplicates(self):
        assert len(CICIDS2018_FEATURES_FULL) == len(set(CICIDS2018_FEATURES_FULL))

    def test_cicids2018_short_not_empty(self):
        assert len(CICIDS2018_FEATURES_SHORT) > 0

    def test_unsw_nb15_not_empty(self):
        assert len(UNSW_NB15_FEATURES) > 0

    def test_unsw_nb15_no_duplicates(self):
        assert len(UNSW_NB15_FEATURES) == len(set(UNSW_NB15_FEATURES))

    def test_cic_iot_2023_expected_features(self):
        """Verify key features exist."""
        expected = ["flow_duration", "Protocol Type", "Rate", "TCP", "UDP", "ICMP"]
        for feat in expected:
            assert feat in CIC_IOT_2023_FEATURES, f"Missing feature: {feat}"
