"""
Unit Tests — Schema Validation (US-1.1 / US-1.2)
==================================================
Validates Pydantic schemas enforce correct data formats:
  - IP address validation
  - MAC address format
  - ENS tag format (op.xxx.N / mp.xxx.N / org.xxx.N)
  - CIDR range validation for Discovery
"""

import pytest
from pydantic import ValidationError

from services.asset_manager.schemas import (
    AssetCreate,
    AssetUpdate,
    DiscoveryRequest,
)


class TestAssetCreateValidation:

    def test_valid_ipv4(self):
        a = AssetCreate(ip="192.168.1.1", responsable="Admin")
        assert a.ip == "192.168.1.1"

    def test_valid_ipv6_full(self):
        """IPv6 address that meets min_length=7 constraint."""
        a = AssetCreate(ip="::ffff:10.0.0.1", responsable="Admin")
        assert a.ip == "::ffff:10.0.0.1"

    def test_valid_ipv6_loopback(self):
        a = AssetCreate(ip="0000::1", responsable="Admin")
        assert a.ip == "0000::1"

    def test_invalid_ip_rejected(self):
        with pytest.raises(ValidationError):
            AssetCreate(ip="not-an-ip-addr", responsable="Admin")

    def test_valid_mac(self):
        a = AssetCreate(
            ip="10.0.0.1", responsable="Admin", mac_address="AA:BB:CC:DD:EE:FF"
        )
        assert a.mac_address == "AA:BB:CC:DD:EE:FF"

    def test_invalid_mac_rejected(self):
        with pytest.raises(ValidationError):
            AssetCreate(ip="10.0.0.1", responsable="Admin", mac_address="ZZZZ")

    def test_valid_ens_tags(self):
        a = AssetCreate(
            ip="10.0.0.1",
            responsable="Admin",
            tags_ens=["op.exp.1", "mp.info.3", "org.gen.1"],
        )
        assert len(a.tags_ens) == 3

    def test_invalid_ens_tag_rejected(self):
        with pytest.raises(ValidationError):
            AssetCreate(
                ip="10.0.0.1", responsable="Admin", tags_ens=["not_valid"]
            )

    def test_responsable_required(self):
        with pytest.raises(ValidationError):
            AssetCreate(ip="10.0.0.1")

    def test_ip_required(self):
        with pytest.raises(ValidationError):
            AssetCreate(responsable="Admin")

    def test_default_criticidad(self):
        a = AssetCreate(ip="10.0.0.1", responsable="Admin")
        assert a.criticidad.value == "PENDIENTE_CLASIFICAR"

    def test_default_tipo(self):
        a = AssetCreate(ip="10.0.0.1", responsable="Admin")
        assert a.tipo.value == "OTRO"

    def test_all_criticidad_values(self):
        for crit in ["BAJA", "MEDIA", "ALTA", "PENDIENTE_CLASIFICAR"]:
            a = AssetCreate(ip="10.0.0.1", responsable="Admin", criticidad=crit)
            assert a.criticidad.value == crit

    def test_all_tipo_values(self):
        for tipo in ["ENDPOINT", "SERVER", "RED", "APLICACION", "IOT", "OTRO"]:
            a = AssetCreate(ip="10.0.0.1", responsable="Admin", tipo=tipo)
            assert a.tipo.value == tipo

    def test_invalid_criticidad_rejected(self):
        with pytest.raises(ValidationError):
            AssetCreate(ip="10.0.0.1", responsable="Admin", criticidad="INEXISTENTE")

    def test_ip_too_short_rejected(self):
        """Schema enforces min_length=7 on IP field."""
        with pytest.raises(ValidationError):
            AssetCreate(ip="::1", responsable="Admin")


class TestAssetUpdateValidation:

    def test_all_fields_optional(self):
        u = AssetUpdate()
        assert u.ip is None

    def test_partial_update_valid(self):
        u = AssetUpdate(criticidad="BAJA")
        assert u.criticidad.value == "BAJA"
        assert u.ip is None

    def test_invalid_ip_in_update(self):
        with pytest.raises(ValidationError):
            AssetUpdate(ip="not-valid-ip-address")


class TestDiscoveryRequestValidation:

    def test_valid_cidr(self):
        d = DiscoveryRequest(network_ranges=["10.0.0.0/24", "192.168.1.0/16"])
        assert len(d.network_ranges) == 2

    def test_invalid_cidr_rejected(self):
        with pytest.raises(ValidationError):
            DiscoveryRequest(network_ranges=["not-a-cidr"])

    def test_empty_ranges_rejected(self):
        with pytest.raises(ValidationError):
            DiscoveryRequest(network_ranges=[])

    def test_default_responsable(self):
        d = DiscoveryRequest(network_ranges=["10.0.0.0/24"])
        assert d.responsable_default == "Pendiente asignar"
