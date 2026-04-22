"""
ScanOPS Vault Client Module

Provides secure credential management using HashiCorp Vault.
Handles storage and retrieval of sensitive data like passwords, API keys, and certificates.

ENS Alto Compliance: Secure credential storage and access control
US Cybersecurity Framework: PR.AC-1 - Identities and credentials are managed
"""

import json
import hvac
from typing import Dict, Any, Optional, Union
from contextlib import contextmanager

from .config import settings
from .scan_logger import ScanLogger


logger = ScanLogger(__name__)


class VaultClient:
    """
    HashiCorp Vault client for secure credential management.

    Provides methods to store, retrieve, and manage sensitive data
    in Vault's key-value store with proper error handling and logging.
    """

    def __init__(
        self,
        vault_addr: Optional[str] = None,
        vault_token: Optional[str] = None,
        mount_point: Optional[str] = None,
        timeout: Optional[int] = None
    ):
        """
        Initialize Vault client.

        Args:
            vault_addr: Vault server address (defaults to settings)
            vault_token: Vault authentication token (defaults to settings)
            mount_point: KV mount point (defaults to settings)
            timeout: Request timeout in seconds (defaults to settings)
        """
        self.vault_addr = vault_addr or settings.vault_addr
        self.vault_token = vault_token or settings.vault_token
        self.mount_point = mount_point or settings.vault_mount_point
        self.timeout = timeout or settings.vault_timeout

        self._client: Optional[hvac.Client] = None
        self._is_connected = False

    @property
    def client(self) -> hvac.Client:
        """Get or create Vault client instance."""
        if self._client is None:
            self._client = hvac.Client(
                url=self.vault_addr,
                token=self.vault_token,
                timeout=self.timeout
            )
        return self._client

    @property
    def is_connected(self) -> bool:
        """Check if client is connected and authenticated."""
        return self._is_connected

    def connect(self) -> bool:
        """
        Establish connection to Vault and verify authentication.

        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            if self.client.is_authenticated():
                self._is_connected = True
                logger.info("Successfully connected to Vault", extra={
                    "vault_addr": self.vault_addr,
                    "mount_point": self.mount_point
                })
                return True
            else:
                logger.error("Vault authentication failed")
                self._is_connected = False
                return False
        except Exception as e:
            logger.error(f"Failed to connect to Vault: {str(e)}", extra={
                "vault_addr": self.vault_addr,
                "error": str(e)
            })
            self._is_connected = False
            return False

    def store_credentials(
        self,
        path: str,
        credentials: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Store credentials in Vault.

        Args:
            path: Vault path for the credentials
            credentials: Dictionary of credential data
            metadata: Optional metadata for the secret

        Returns:
            bool: True if storage successful, False otherwise
        """
        if not self.is_connected and not self.connect():
            return False

        try:
            full_path = f"{self.mount_point}/{path}"
            data = {"data": credentials}

            if metadata:
                data["metadata"] = metadata

            response = self.client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret=data,
                mount_point=self.mount_point
            )

            logger.info("Credentials stored successfully", extra={
                "path": full_path,
                "version": response.get('data', {}).get('version')
            })
            return True

        except Exception as e:
            logger.error(f"Failed to store credentials: {str(e)}", extra={
                "path": f"{self.mount_point}/{path}",
                "error": str(e)
            })
            return False

    def read_credentials(
        self,
        path: str,
        version: Optional[int] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Read credentials from Vault.

        Args:
            path: Vault path for the credentials
            version: Optional version number to read

        Returns:
            Dict containing credentials or None if not found
        """
        if not self.is_connected and not self.connect():
            return None

        try:
            response = self.client.secrets.kv.v2.read_secret_version(
                path=path,
                version=version,
                mount_point=self.mount_point
            )

            data = response.get('data', {}).get('data', {})
            if data:
                logger.info("Credentials retrieved successfully", extra={
                    "path": f"{self.mount_point}/{path}",
                    "version": response.get('data', {}).get('metadata', {}).get('version')
                })
                return data
            else:
                logger.warning("No credentials found", extra={
                    "path": f"{self.mount_point}/{path}"
                })
                return None

        except Exception as e:
            logger.error(f"Failed to read credentials: {str(e)}", extra={
                "path": f"{self.mount_point}/{path}",
                "error": str(e)
            })
            return None

    def delete_credentials(self, path: str) -> bool:
        """
        Delete credentials from Vault.

        Args:
            path: Vault path for the credentials

        Returns:
            bool: True if deletion successful, False otherwise
        """
        if not self.is_connected and not self.connect():
            return False

        try:
            self.client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=path,
                mount_point=self.mount_point
            )

            logger.info("Credentials deleted successfully", extra={
                "path": f"{self.mount_point}/{path}"
            })
            return True

        except Exception as e:
            logger.error(f"Failed to delete credentials: {str(e)}", extra={
                "path": f"{self.mount_point}/{path}",
                "error": str(e)
            })
            return False

    def list_credentials(self, path: str = "") -> Optional[list]:
        """
        List credential paths under the given path.

        Args:
            path: Base path to list (empty string for root)

        Returns:
            List of credential paths or None if error
        """
        if not self.is_connected and not self.connect():
            return None

        try:
            response = self.client.secrets.kv.v2.list_secrets_version(
                path=path,
                mount_point=self.mount_point
            )

            keys = response.get('data', {}).get('keys', [])
            logger.info("Credentials listed successfully", extra={
                "path": f"{self.mount_point}/{path}",
                "count": len(keys)
            })
            return keys

        except Exception as e:
            logger.error(f"Failed to list credentials: {str(e)}", extra={
                "path": f"{self.mount_point}/{path}",
                "error": str(e)
            })
            return None

    def update_credentials(
        self,
        path: str,
        updates: Dict[str, Any],
        merge: bool = True
    ) -> bool:
        """
        Update existing credentials in Vault.

        Args:
            path: Vault path for the credentials
            updates: Dictionary of updates to apply
            merge: Whether to merge with existing data or replace

        Returns:
            bool: True if update successful, False otherwise
        """
        if merge:
            existing = self.read_credentials(path)
            if existing is None:
                logger.warning("Cannot merge - credentials not found", extra={
                    "path": f"{self.mount_point}/{path}"
                })
                return False
            updates = {**existing, **updates}

        return self.store_credentials(path, updates)

    @contextmanager
    def temporary_credentials(self, path: str, credentials: Dict[str, Any]):
        """
        Context manager for temporary credential storage.

        Stores credentials for the duration of the context, then deletes them.

        Args:
            path: Vault path for temporary storage
            credentials: Credentials to store temporarily
        """
        temp_path = f"temp/{path}"
        stored = self.store_credentials(temp_path, credentials)

        if not stored:
            raise RuntimeError(f"Failed to store temporary credentials at {temp_path}")

        try:
            yield temp_path
        finally:
            self.delete_credentials(temp_path)


# Global vault client instance
vault_client = VaultClient()
