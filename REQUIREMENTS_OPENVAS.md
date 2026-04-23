# Requisitos para Integración con OpenVAS (GVM)

Para que el módulo **Scanner Engine (M3)** funcione correctamente con el cliente real de OpenVAS, se deben cumplir los siguientes requisitos técnicos:

## 1. Servidor GVM (Greenbone Vulnerability Manager)
*   **Acceso Red**: El servidor debe ser accesible desde el contenedor de ScanOPS por el puerto GMP (normalmente TCP 9390).
*   **Protocolo**: Se utiliza **GMP (Greenbone Management Protocol)** sobre TLS.
*   **Certificados**: Si el servidor utiliza certificados auto-firmados (self-signed), asegúrate de que la CA esté en el trust-store del contenedor o configura `GVM_VERIFY_CERT=False` (si se implementa el override).

## 2. Credenciales (Variables de Entorno)
El archivo `.env` debe contener:
```bash
OPENVAS_HOST=10.202.15.200
OPENVAS_PORT=9390
OPENVAS_USER=admin
OPENVAS_PASS=TuPasswordSeguro
```

## 3. Configuración de Escaneo (UUIDs)
El cliente utiliza los siguientes UUIDs estándar de Greenbone. Si tu instalación es personalizada, verifica estos IDs:
*   **Port List**: `33d0cd10-f6ec-11e0-815c-002264764cea` (All IANA relevant TCP)
*   **Scan Config**: `daba56c8-73ec-11df-a475-002264764cea` (Full and fast)
*   **Scanner**: `08b69003-5fc2-45d1-a82e-ab9734732d91` (OpenVAS Default)

## 4. Notas de Rendimiento
*   **Timeouts**: Los escaneos de OpenVAS pueden tardar desde minutos hasta horas dependiendo del activo. El sistema tiene un timeout por defecto de **1 hora** (3600s).
*   **Concurrencia**: No se recomienda lanzar más de 5 escaneos simultáneos contra el mismo servidor GVM para evitar bloqueos del demonio `openvas`.
