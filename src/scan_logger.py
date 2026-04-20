import logging
import os
import json
from datetime import datetime


class ScanLogger:
    """
    Sistema centralizado de logging para auditoría UNUWARE.
    Crea automáticamente la carpeta logs/ y escribe a logs/scanops_audit.log
    """
    
    _log_dir = "logs"
    _log_file = "logs/scanops_audit.log"
    _logger = None
    
    def __init__(self, module_name):
        """
        Inicializa el logger para un módulo específico.
        
        Args:
            module_name: Nombre del módulo (ej: "main_orchestrator", "scanner_network")
        """
        self.module_name = module_name
        
        # Crear carpeta logs/ si no existe (solo una vez)
        if not os.path.exists(self._log_dir):
            os.makedirs(self._log_dir)
        
        # Configurar el logger global si no existe
        if ScanLogger._logger is None:
            ScanLogger._logger = logging.getLogger("ScanOps")
            ScanLogger._logger.setLevel(logging.DEBUG)
            
            # Handler para archivo
            file_handler = logging.FileHandler(self._log_file, encoding='utf-8')
            file_handler.setLevel(logging.DEBUG)
            
            # Formato: timestamp | level | module | event | JSON data
            formatter = logging.Formatter(
                '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            file_handler.setFormatter(formatter)
            
            ScanLogger._logger.addHandler(file_handler)
    
    def _format_event(self, event_type, **kwargs):
        """Formatea un evento con sus parámetros en JSON."""
        event_data = {
            "event": event_type,
            "module": self.module_name,
            "timestamp": datetime.now().isoformat(),
        }
        event_data.update(kwargs)
        return json.dumps(event_data, ensure_ascii=False)
    
    def info(self, event, **kwargs):
        """Log de información."""
        message = self._format_event(event, **kwargs)
        ScanLogger._logger.info(message)
    
    def warning(self, event, **kwargs):
        """Log de advertencia."""
        message = self._format_event(event, **kwargs)
        ScanLogger._logger.warning(message)
    
    def error(self, event, **kwargs):
        """Log de error."""
        message = self._format_event(event, **kwargs)
        ScanLogger._logger.error(message)
    
    def scan_start(self, target, **kwargs):
        """Log para inicio de escaneo."""
        self.info("SCAN_START", target=target, **kwargs)
    
    def scan_end(self, target, **kwargs):
        """Log para fin de escaneo."""
        self.info("SCAN_END", target=target, **kwargs)
    
    def finding(self, name, severity=None, status=None, **kwargs):
        """Log para un hallazgo de seguridad."""
        self.info("FINDING", name=name, severity=severity, status=status, **kwargs)
    
    def auth_event(self, auth_type, target=None, success=None, **kwargs):
        """Log para eventos de autenticación."""
        self.info("AUTH_EVENT", auth_type=auth_type, target=target, success=success, **kwargs)
    
    def module_error(self, message, target=None, **kwargs):
        """Log para errores en módulos."""
        self.error("MODULE_ERROR", message=message, target=target, **kwargs)
    
    def compliance(self, status, measure=None, **kwargs):
        """Log para cumplimiento normativo."""
        self.info("COMPLIANCE", status=status, measure=measure, **kwargs)
