"""Unit tests for threat_service helper functions."""

import pytest

from app.services.threat_service import _millis_to_datetime, _map_source, _map_label
from app.models.threat import ThreatSource, ThreatLabel


class TestMillisToDatetime:
    def test_valid_millis(self):
        from datetime import datetime
        dt = _millis_to_datetime(1_700_000_000_000)
        assert isinstance(dt, datetime)
        assert dt.year == 2023

    def test_zero_returns_none(self):
        assert _millis_to_datetime(0) is None

    def test_negative_returns_none(self):
        assert _millis_to_datetime(-1) is None

    def test_none_returns_none(self):
        assert _millis_to_datetime(None) is None  # type: ignore[arg-type]

    def test_recent_timestamp(self):
        # 2026-01-01 00:00:00 UTC in millis
        millis = 1_767_225_600_000
        dt = _millis_to_datetime(millis)
        assert dt is not None
        assert dt.year == 2026


class TestMapSource:
    def test_auto_sms(self):
        assert _map_source("AUTO_SMS") == ThreatSource.AUTO_SMS

    def test_auto_telegram(self):
        assert _map_source("AUTO_TELEGRAM") == ThreatSource.AUTO_TELEGRAM

    def test_manual(self):
        assert _map_source("MANUAL") == ThreatSource.MANUAL

    def test_scanner_domain(self):
        assert _map_source("SCANNER_DOMAIN") == ThreatSource.SCANNER_DOMAIN

    def test_unknown_defaults_to_manual(self):
        assert _map_source("UNKNOWN_SOURCE") == ThreatSource.MANUAL

    def test_empty_string_defaults_to_manual(self):
        assert _map_source("") == ThreatSource.MANUAL

    def test_lowercase_not_recognised(self):
        # Enum values are uppercase — lowercase should fall back to MANUAL
        assert _map_source("auto_sms") == ThreatSource.MANUAL


class TestMapLabel:
    def test_dangerous(self):
        assert _map_label("DANGEROUS") == ThreatLabel.DANGEROUS

    def test_suspicious(self):
        assert _map_label("SUSPICIOUS") == ThreatLabel.SUSPICIOUS

    def test_safe(self):
        assert _map_label("SAFE") == ThreatLabel.SAFE

    def test_unknown_defaults_to_dangerous(self):
        assert _map_label("INVALID") == ThreatLabel.DANGEROUS

    def test_empty_string_defaults_to_dangerous(self):
        assert _map_label("") == ThreatLabel.DANGEROUS
