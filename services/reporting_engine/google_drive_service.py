import io
import logging
import os
from typing import Optional  # <-- Corregido: Importación añadida para evitar el NameError
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload

logger = logging.getLogger("m7.google_drive")


SCOPES = ['https://www.googleapis.com/auth/drive']  # <-- Al quitar '.file', le permites escribir en tu carpeta compartida

# Buscar el archivo de claves de forma dinámica (local o raíz del contenedor)
SERVICE_ACCOUNT_FILE = 'service_account.json'
if not os.path.exists(SERVICE_ACCOUNT_FILE):
    SERVICE_ACCOUNT_FILE = 'services/reporting_engine/service_account.json'

class GoogleDriveService:
    def __init__(self):
        self.folder_id = os.getenv("GOOGLE_DRIVE_FOLDER_ID", None)
        self.service = self._authenticate()

    def _authenticate(self):
        """Autentica de forma silenciosa usando la Cuenta de Servicio."""
        if not os.path.exists(SERVICE_ACCOUNT_FILE):
            logger.warning(f"⚠️ Archivo de credenciales no encontrado en ruta. Subida a Drive en stand-by.")
            return None
        try:
            creds = service_account.Credentials.from_service_account_file(
                SERVICE_ACCOUNT_FILE, scopes=SCOPES
            )
            return build('drive', 'v3', credentials=creds)
        except Exception as e:
            logger.error(f"❌ Error crítico de autenticación en Google Drive API: {e}")
            return None

    def _upload_bytes(self, filename: str, data: bytes, mimetype: str) -> Optional[str]:
        """Sube bytes a Drive con el mimetype indicado."""
        if not self.service:
            logger.warning("⚠️ Servicio de Google Drive no inicializado. Omitiendo subida.")
            return None
        try:
            file_metadata: dict = {'name': filename, 'mimeType': mimetype}
            if self.folder_id:
                file_metadata['parents'] = [self.folder_id]
            media = MediaIoBaseUpload(io.BytesIO(data), mimetype=mimetype, resumable=False)
            file = self.service.files().create(
                body=file_metadata,
                media_body=media,
                fields='id',
                supportsAllDrives=True,
            ).execute()
            drive_id = file.get('id')
            logger.info(f"✅ Subido a Google Drive: {filename} (ID: {drive_id})")
            return drive_id
        except Exception as e:
            logger.error(f"❌ Error subiendo {filename} a Google Drive: {e}")
            return None

    def upload_pdf(self, filename: str, pdf_bytes: bytes) -> Optional[str]:
        """Sube los bytes de un PDF a la carpeta de Drive designada."""
        return self._upload_bytes(filename, pdf_bytes, 'application/pdf')

    def upload_zip(self, filename: str, zip_bytes: bytes) -> Optional[str]:
        """Sube un ZIP de auditoría completa a la carpeta de Drive designada."""
        return self._upload_bytes(filename, zip_bytes, 'application/zip')

drive_uploader = GoogleDriveService()