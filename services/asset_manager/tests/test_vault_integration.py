"""
Integration Tests — Vault Integration (US-1.3)
================================================
Validates that credentials flow through Vault correctly:
  - Passwords are never stored in the DB
  - vault_path is set when password is provided
  - Vault client is called with correct parameters
"""

import pytest


class TestVaultIntegration:
    """Credential storage through Vault [mp.info.3]"""

    def test_password_not_in_db_response(self, client, auth_headers, mock_vault):
        payload = {
            "ip": "10.0.0.10",
            "responsable": "SecOps",
            "password": "TopSecret!2026",
        }
        resp = client.post("/assets", json=payload, headers=auth_headers)
        assert resp.status_code == 201
        body = resp.json()
        # Password must NEVER appear in the response
        assert "TopSecret!2026" not in str(body)
        assert "password" not in body or body.get("password") is None

    def test_vault_path_format(self, client, auth_headers, mock_vault):
        payload = {
            "ip": "10.0.0.11",
            "responsable": "SecOps",
            "password": "MyPass123",
        }
        resp = client.post("/assets", json=payload, headers=auth_headers)
        body = resp.json()
        assert body["vault_path"] is not None
        assert body["vault_path"].startswith("assets/")
        assert "/credentials" in body["vault_path"]

    def test_vault_store_called_with_password(self, client, auth_headers, mock_vault):
        payload = {
            "ip": "10.0.0.12",
            "responsable": "SecOps",
            "password": "VaultMe!",
        }
        client.post("/assets", json=payload, headers=auth_headers)
        mock_vault.store_credentials.assert_called_once()
        call_args = mock_vault.store_credentials.call_args
        # Verify the password was sent to Vault
        assert call_args[0][1] == {"password": "VaultMe!"}

    def test_no_vault_call_without_password(self, client, auth_headers, mock_vault):
        payload = {"ip": "10.0.0.13", "responsable": "Admin"}
        client.post("/assets", json=payload, headers=auth_headers)
        mock_vault.store_credentials.assert_not_called()

    def test_vault_path_none_without_password(self, client, auth_headers, mock_vault):
        payload = {"ip": "10.0.0.14", "responsable": "Admin"}
        resp = client.post("/assets", json=payload, headers=auth_headers)
        assert resp.json()["vault_path"] is None
