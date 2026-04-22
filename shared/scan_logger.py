import logging
import os
import json
from datetime import datetime


class ScanLogger:
    """Centralized logging for ScanOPS microservices."""

    _log_dir = "logs"
    _log_file = "logs/scanops_audit.log"
    _logger = None

    def __init__(self, module_name: str):
        self.module_name = module_name
        if not os.path.exists(self._log_dir):
            os.makedirs(self._log_dir)

        if ScanLogger._logger is None:
            ScanLogger._logger = logging.getLogger("ScanOps")
            ScanLogger._logger.setLevel(logging.DEBUG)
            file_handler = logging.FileHandler(self._log_file, encoding="utf-8")
            file_handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter(
                '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            file_handler.setFormatter(formatter)
            ScanLogger._logger.addHandler(file_handler)

    def _format_event(self, event_type: str, **kwargs) -> str:
        event_data = {
            "event": event_type,
            "module": self.module_name,
            "timestamp": datetime.now().isoformat(),
        }
        event_data.update(kwargs)
        return json.dumps(event_data, ensure_ascii=False)

    def info(self, event: str, **kwargs):
        ScanLogger._logger.info(self._format_event(event, **kwargs))

    def warning(self, event: str, **kwargs):
        ScanLogger._logger.warning(self._format_event(event, **kwargs))

    def error(self, event: str, **kwargs):
        ScanLogger._logger.error(self._format_event(event, **kwargs))

    def scan_start(self, target: str, **kwargs):
        self.info("SCAN_START", target=target, **kwargs)

    def scan_end(self, target: str, **kwargs):
        self.info("SCAN_END", target=target, **kwargs)

    def finding(self, name: str, severity=None, status=None, **kwargs):
        self.info("FINDING", name=name, severity=severity, status=status, **kwargs)

    def auth_event(self, auth_type: str, target=None, success=None, **kwargs):
        self.info("AUTH_EVENT", auth_type=auth_type, target=target, success=success, **kwargs)

    def module_error(self, message: str, target=None, **kwargs):
        self.error("MODULE_ERROR", message=message, target=target, **kwargs)

    def compliance(self, status: str, measure=None, **kwargs):
        self.info("COMPLIANCE", status=status, measure=measure, **kwargs)
