"""
Unit Tests — Asset Model (US-1.1)
==================================
Tests the SQLAlchemy models directly, including enums,
soft-delete, and relationships.
"""

import pytest
from datetime import datetime

from services.asset_manager.models.asset import (
    Asset,
    AssetAuditLog,
    CriticidadEnum,
    TipoActivoEnum,
    AssetStatusEnum,
    AuditActionEnum,
)


class TestAssetModel:

    def test_create_asset_minimal(self, test_db):
        asset = Asset(ip="10.0.0.1", responsable="Admin")
        test_db.add(asset)
        test_db.commit()
        assert asset.id is not None
        assert asset.criticidad == CriticidadEnum.PENDIENTE_CLASIFICAR
        assert asset.tipo == TipoActivoEnum.OTRO
        assert asset.status == AssetStatusEnum.ACTIVO
        assert asset.is_active is True

    def test_create_asset_full(self, test_db, sample_asset_data):
        asset = Asset(**sample_asset_data)
        test_db.add(asset)
        test_db.commit()
        assert asset.ip == "10.202.15.100"
        assert asset.hostname == "srv-auditoria-01"
        assert asset.criticidad == CriticidadEnum.ALTA
        assert asset.tipo == TipoActivoEnum.SERVER
        assert asset.tags_ens == ["op.exp.1", "op.acc.6"]

    def test_soft_delete(self, test_db, sample_asset_data):
        asset = Asset(**sample_asset_data)
        test_db.add(asset)
        test_db.commit()
        asset.soft_delete()
        test_db.commit()
        assert asset.deleted_at is not None
        assert asset.status == AssetStatusEnum.BAJA
        assert asset.is_active is False

    def test_soft_delete_preserves_record(self, test_db, sample_asset_data):
        asset = Asset(**sample_asset_data)
        test_db.add(asset)
        test_db.commit()
        asset_id = asset.id
        asset.soft_delete()
        test_db.commit()
        found = test_db.query(Asset).filter(Asset.id == asset_id).first()
        assert found is not None
        assert found.deleted_at is not None

    def test_vault_path_no_credentials(self, test_db, sample_asset_data):
        sample_asset_data["vault_path"] = "secret/assets/42"
        asset = Asset(**sample_asset_data)
        test_db.add(asset)
        test_db.commit()
        assert asset.vault_path == "secret/assets/42"
        assert "password" not in str(asset.__dict__)

    def test_created_at_auto(self, test_db):
        asset = Asset(ip="10.0.0.1", responsable="Admin")
        test_db.add(asset)
        test_db.commit()
        assert asset.created_at is not None

    def test_all_status_values(self, test_db):
        for status in AssetStatusEnum:
            asset = Asset(ip="10.0.0.1", responsable="Admin", status=status)
            test_db.add(asset)
            test_db.commit()
            assert asset.status == status
            test_db.delete(asset)
            test_db.commit()


class TestAuditLogModel:

    def test_create_audit_log(self, test_db, sample_asset_data):
        asset = Asset(**sample_asset_data)
        test_db.add(asset)
        test_db.commit()
        log = AssetAuditLog(
            asset_id=asset.id,
            action=AuditActionEnum.CREATE,
            user_id="borja",
            user_role="resp_sistema",
            snapshot_after={"ip": "10.202.15.100"},
        )
        test_db.add(log)
        test_db.commit()
        assert log.id is not None
        assert log.asset_id == asset.id
        assert log.action == AuditActionEnum.CREATE

    def test_audit_log_relationship(self, test_db, sample_asset_data):
        asset = Asset(**sample_asset_data)
        test_db.add(asset)
        test_db.commit()
        for action in [AuditActionEnum.CREATE, AuditActionEnum.UPDATE]:
            log = AssetAuditLog(
                asset_id=asset.id, action=action, user_id="borja"
            )
            test_db.add(log)
        test_db.commit()
        test_db.refresh(asset)
        assert len(asset.audit_logs) == 2

    def test_audit_log_changes_tracking(self, test_db, sample_asset_data):
        asset = Asset(**sample_asset_data)
        test_db.add(asset)
        test_db.commit()
        log = AssetAuditLog(
            asset_id=asset.id,
            action=AuditActionEnum.UPDATE,
            user_id="borja",
            changes={"criticidad": {"old": "ALTA", "new": "MEDIA"}},
            snapshot_before={"criticidad": "ALTA"},
            snapshot_after={"criticidad": "MEDIA"},
        )
        test_db.add(log)
        test_db.commit()
        assert log.changes["criticidad"]["old"] == "ALTA"
        assert log.changes["criticidad"]["new"] == "MEDIA"

    def test_all_audit_actions(self, test_db, sample_asset_data):
        asset = Asset(**sample_asset_data)
        test_db.add(asset)
        test_db.commit()
        for action in AuditActionEnum:
            log = AssetAuditLog(
                asset_id=asset.id, action=action, user_id="test"
            )
            test_db.add(log)
        test_db.commit()
        assert len(asset.audit_logs) == len(AuditActionEnum)

    def test_timestamp_auto(self, test_db, sample_asset_data):
        asset = Asset(**sample_asset_data)
        test_db.add(asset)
        test_db.commit()
        log = AssetAuditLog(
            asset_id=asset.id, action=AuditActionEnum.CREATE, user_id="test"
        )
        test_db.add(log)
        test_db.commit()
        assert log.timestamp is not None
