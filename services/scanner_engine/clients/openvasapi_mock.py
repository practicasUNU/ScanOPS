class OpenvasConnection:
    def __init__(self, host, username, password):
        self.host = host
    def create_target(self, name, hosts):
        return f"target_{name}"
    def start_scan(self, target_id, scan_type):
        return f"task_{target_id}"
    def task_status(self, task_id):
        return 100
    def get_results(self, task_id):
        return [{'nvt_oid': 'CVE-2024-1234', 'nvt_name': 'Test CVE', 'severity': '7.5', 'cvss': 7.5, 'port': 443}]
