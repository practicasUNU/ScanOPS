"""
Unit Tests — Asset Service Layer (US-1.2)
==========================================
Tests the business logic in asset_service.py directly
(no HTTP, no FastAPI), using SQLite in-memory.
"""

import pytest
from unittest.mock import patch, MagicMock

from services.asset_manager.models.asset import (
    Asset,
    AssetAuditLog,
    CriticidadEnum,
    TipoActivoEnum,
    AssetStatusEnum,
    AuditActionEnum,
)
from services.asset_manager.schemas import AssetCreate, AssetUpdate
from services.asset_manager.services import asset_service


@pytest.fixture
def mock_vault_svc():
    """Patch vault_client at the service module level."""
    mock = MagicMock()
    mock.store_credentials = MagicMock(return_value=True)
    mock.connect = MagicMock(return_value=True)
    mock.is_connected = True
    with patch("services.asset_manager.services.asset_service.vault_client", mock):
        yield mock


class TestCreateAssetService:

    def test_create_basic(self, test_db, mock_vault_svc):
        data = AssetCreate(ip="10.0.0.1", responsable="Admin")
        asset = asset_service.create_asset(test_db, data, user_id="test")
        assert asset.id is not None
        assert asset.ip == "10.0.0.1"
        assert asset.criticidad == CriticidadEnum.PENDIENTE_CLASIFICAR

    def test_create_with_all_fields(self, test_db, mock_vault_svc, sample_asset_data):
        data = AssetCreate(**sample_asset_data)
        asset = asset_service.create_asset(test_db, data, user_id="test")
        assert asset.hostname == "srv-auditoria-01"
        assert asset.criticidad == CriticidadEnum.ALTA
        assert asset.tags_ens == ["op.exp.1", "op.acc.6"]

    def test_create_with_password_sets_vault_path(self, test_db, mock_vault_svc):
        data = AssetCreate(ip="10.0.0.2", responsable="Admin", password="secret")
        asset = asset_service.create_asset(test_db, data, user_id="test")
        assert asset.vault_path is not None
        assert asset.vault_path.startswith("assets/")
        mock_vault_svc.store_credentials.assert_called_once()

    def test_create_generates_audit_log(self, test_db, mock_vault_svc):
        data = AssetCreate(ip="10.0.0.3", responsable="Admin")
        asset = asset_service.create_asset(test_db, data, user_id="borja")
        logs = test_db.query(AssetAuditLog).filter_by(asset_id=asset.id).all()
        assert len(logs) >= 1


class TestGetAssetService:

    def test_get_existing(self, test_db, mock_vault_svc):
        data = AssetCreate(ip="10.0.0.1", responsable="Admin")
        created = asset_service.create_asset(test_db, data, user_id="test")
        found = asset_service.get_asset(test_db, created.id)
        assert found is not None
        assert found.id == created.id

    def test_get_nonexistent(self, test_db):
        assert asset_service.get_asset(test_db, 9999) is None

    def test_get_deleted_excluded_by_default(self, test_db, mock_vault_svc):
        data = AssetCreate(ip="10.0.0.1", responsable="Admin")
        created = asset_service.create_asset(test_db, data, user_id="test")
        asset_service.delete_asset(test_db, created.id, user_id="test")
        assert asset_service.get_asset(test_db, created.id) is None

    def test_get_deleted_included_when_requested(self, test_db, mock_vault_svc):
        data = AssetCreate(ip="10.0.0.1", responsable="Admin")
        created = asset_service.create_asset(test_db, data, user_id="test")
        asset_service.delete_asset(test_db, created.id, user_id="test")
        found = asset_service.get_asset(test_db, created.id, include_deleted=True)
        assert found is not None

    def test_get_by_ip(self, test_db, mock_vault_svc):
        data = AssetCreate(ip="172.16.0.1", responsable="Admin")
        asset_service.create_asset(test_db, data, user_id="test")
        found = asset_service.get_asset_by_ip(test_db, "172.16.0.1")
        assert found is not None
        assert found.ip == "172.16.0.1"


class TestListAssetsService:

    def test_list_empty(self, test_db):
        items, total = asset_service.list_assets(test_db)
        assert total == 0
        assert items == []

    def test_list_with_filters(self, test_db, mock_vault_svc):
        for i, crit in enumerate(["ALTA", "BAJA", "ALTA"]):
            data = AssetCreate(
                ip=f"10.0.0.{i+1}", responsable="Admin", criticidad=crit
            )
            asset_service.create_asset(test_db, data, user_id="test")

        items, total = asset_service.list_assets(
            test_db, criticidad=CriticidadEnum.ALTA
        )
        assert total == 2

    def test_list_search(self, test_db, mock_vault_svc):
        data = AssetCreate(
            ip="10.0.0.1", responsable="Admin", hostname="web-server"
        )
        asset_service.create_asset(test_db, data, user_id="test")
        items, total = asset_service.list_assets(test_db, search="web-server")
        assert total == 1


class TestUpdateAssetService:

    def test_update_changes_field(self, test_db, mock_vault_svc):
        data = AssetCreate(ip="10.0.0.1", responsable="Admin", criticidad="ALTA")
        asset = asset_service.create_asset(test_db, data, user_id="test")
        updated = asset_service.update_asset(
            test_db, asset.id, AssetUpdate(criticidad="BAJA"), user_id="test"
        )
        assert updated.criticidad == CriticidadEnum.BAJA

    def test_update_generates_audit_with_changes(self, test_db, mock_vault_svc):
        data = AssetCreate(ip="10.0.0.1", responsable="Admin", criticidad="ALTA")
        asset = asset_service.create_asset(test_db, data, user_id="test")
        asset_service.update_asset(
            test_db, asset.id, AssetUpdate(criticidad="BAJA"), user_id="test"
        )
        logs = (
            test_db.query(AssetAuditLog)
            .filter_by(asset_id=asset.id, action=AuditActionEnum.UPDATE)
            .all()
        )
        assert len(logs) == 1

    def test_update_no_change_skips_audit(self, test_db, mock_vault_svc):
        data = AssetCreate(ip="10.0.0.1", responsable="Admin", criticidad="ALTA")
        asset = asset_service.create_asset(test_db, data, user_id="test")
        initial_logs = test_db.query(AssetAuditLog).filter_by(asset_id=asset.id).count()
        asset_service.update_asset(
            test_db, asset.id, AssetUpdate(criticidad="ALTA"), user_id="test"
        )
        final_logs = test_db.query(AssetAuditLog).filter_by(asset_id=asset.id).count()
        assert final_logs == initial_logs  # no new log

    def test_update_nonexistent(self, test_db):
        result = asset_service.update_asset(
            test_db, 9999, AssetUpdate(criticidad="BAJA"), user_id="test"
        )
        assert result is None


class TestDeleteAssetService:

    def test_soft_delete(self, test_db, mock_vault_svc):
        data = AssetCreate(ip="10.0.0.1", responsable="Admin")
        asset = asset_service.create_asset(test_db, data, user_id="test")
        deleted = asset_service.delete_asset(test_db, asset.id, user_id="test")
        assert deleted.status == AssetStatusEnum.BAJA
        assert deleted.deleted_at is not None

    def test_delete_generates_audit(self, test_db, mock_vault_svc):
        data = AssetCreate(ip="10.0.0.1", responsable="Admin")
        asset = asset_service.create_asset(test_db, data, user_id="test")
        asset_service.delete_asset(test_db, asset.id, user_id="test")
        logs = (
            test_db.query(AssetAuditLog)
            .filter_by(asset_id=asset.id, action=AuditActionEnum.DELETE)
            .all()
        )
        assert len(logs) == 1

    def test_delete_nonexistent(self, test_db):
        assert asset_service.delete_asset(test_db, 9999, user_id="test") is None


class TestAuditLogService:

    def test_get_audit_logs(self, test_db, mock_vault_svc):
        data = AssetCreate(ip="10.0.0.1", responsable="Admin")
        asset = asset_service.create_asset(test_db, data, user_id="test")
        asset_service.update_asset(
            test_db, asset.id, AssetUpdate(hostname="new"), user_id="test"
        )
        items, total = asset_service.get_audit_logs(test_db, asset.id)
        assert total >= 2  # create + update

    def test_audit_log_limit(self, test_db, mock_vault_svc):
        data = AssetCreate(ip="10.0.0.1", responsable="Admin")
        asset = asset_service.create_asset(test_db, data, user_id="test")
        for i in range(5):
            asset_service.update_asset(
                test_db, asset.id, AssetUpdate(hostname=f"h{i}"), user_id="test"
            )
        items, total = asset_service.get_audit_logs(test_db, asset.id, limit=2)
        assert len(items) == 2
        assert total >= 5
