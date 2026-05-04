#!/usr/bin/env python3
"""
M2 Recon Engine - Test Client
==============================
Test script to verify M2 functionality.

Usage:
    python3 m2_client.py --target 10.202.15.100 --subdomains
"""

import requests
import json
import time
import argparse
import sys
from datetime import datetime
from typing import Dict, Optional

BASE_URL = "http://localhost:8003"
TOKEN = "scanops_secret"

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json"
}

class M2Client:
    """Client for M2 Recon Engine API."""
    
    def __init__(self, base_url: str = BASE_URL, token: str = TOKEN):
        self.base_url = base_url
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
    
    def health(self) -> Dict:
        """Check M2 health status."""
        try:
            resp = requests.get(f"{self.base_url}/health", timeout=5)
            return resp.json()
        except Exception as e:
            return {"status": "offline", "error": str(e)}
    
    def info(self) -> Dict:
        """Get M2 service info."""
        resp = requests.get(f"{self.base_url}/info", timeout=5)
        return resp.json()
    
    def start_scan(self, target_ip: str, scan_type: str = "full", 
                   include_subdomain_discovery: bool = False) -> Dict:
        """Start a new reconnaissance scan."""
        params = {
            "target_ip": target_ip,
            "scan_type": scan_type,
            "include_subdomain_discovery": include_subdomain_discovery
        }
        resp = requests.post(
            f"{self.base_url}/api/v1/scan",
            params=params,
            headers=self.headers,
            timeout=10
        )
        return resp.json()
    
    def list_snapshots(self) -> Dict:
        """List all snapshots."""
        resp = requests.get(
            f"{self.base_url}/api/v1/snapshots",
            headers=self.headers,
            timeout=10
        )
        return resp.json()
    
    def get_findings(self, snapshot_id: str) -> Dict:
        """Get findings from a snapshot."""
        resp = requests.get(
            f"{self.base_url}/api/v1/snapshots/{snapshot_id}/findings",
            headers=self.headers,
            timeout=10
        )
        return resp.json()
    
    def get_subdomains(self, snapshot_id: str) -> Dict:
        """Get subdomains from a snapshot."""
        resp = requests.get(
            f"{self.base_url}/api/v1/snapshots/{snapshot_id}/subdomains",
            headers=self.headers,
            timeout=10
        )
        return resp.json()
    
    def surface_diff(self, snapshot_id: Optional[str] = None) -> Dict:
        """Get surface diff for a snapshot."""
        params = {}
        if snapshot_id:
            params["snapshot_id"] = snapshot_id
        
        resp = requests.get(
            f"{self.base_url}/api/v1/surface-diff",
            params=params,
            headers=self.headers,
            timeout=10
        )
        return resp.json()

def print_header(text: str):
    """Print formatted header."""
    print(f"\n{'=' * 70}")
    print(f"  {text}")
    print(f"{'=' * 70}\n")

def print_json(data: Dict, indent: int = 2):
    """Pretty print JSON."""
    print(json.dumps(data, indent=indent, ensure_ascii=False))

def main():
    """Main test function."""
    parser = argparse.ArgumentParser(description="M2 Recon Engine Test Client")
    parser.add_argument("--target", type=str, default="10.202.15.100", 
                       help="Target IP to scan (default: 10.202.15.100)")
    parser.add_argument("--subdomains", action="store_true", 
                       help="Include subdomain discovery")
    parser.add_argument("--wait", type=int, default=3, 
                       help="Wait time before checking results (seconds)")
    parser.add_argument("--url", type=str, default=BASE_URL, 
                       help="M2 base URL (default: http://localhost:8002)")
    
    args = parser.parse_args()
    
    client = M2Client(base_url=args.url)
    
    # 1. Check health
    print_header("1. HEALTH CHECK")
    health = client.health()
    print_json(health)
    
    if health.get("status") != "ok":
        print("[X] M2 is not responding. Make sure it's running:")
        print("  python3 m2_main.py")
        sys.exit(1)
    
    # 2. Get service info
    print_header("2. SERVICE INFO")
    info = client.info()
    print_json(info)
    
    # 3. Start scan
    print_header(f"3. STARTING SCAN - Target: {args.target}")
    scan_result = client.start_scan(
        target_ip=args.target,
        scan_type="full",
        include_subdomain_discovery=args.subdomains
    )
    print_json(scan_result)
    
    snapshot_id = scan_result.get("snapshot_id")
    print(f"\n[*] Snapshot ID: {snapshot_id}")
    print(f"[*] Waiting {args.wait} seconds for scan to complete...")
    time.sleep(args.wait)
    
    # 4. List snapshots
    print_header("4. AVAILABLE SNAPSHOTS")
    snapshots = client.list_snapshots()
    print_json(snapshots)
    
    if not snapshot_id:
        print("[X] No snapshot ID obtained")
        return
    
    # 5. Get findings
    print_header(f"5. FINDINGS - Snapshot: {snapshot_id}")
    findings = client.get_findings(snapshot_id)
    print_json(findings)
    
    findings_count = findings.get("findings_count", 0)
    print(f"\n[V] Found {findings_count} open ports")
    
    # 6. Get subdomains (if enabled)
    if args.subdomains:
        print_header(f"6. SUBDOMAINS - Snapshot: {snapshot_id}")
        subdomains = client.get_subdomains(snapshot_id)
        print_json(subdomains)
        subdomain_count = subdomains.get("count", 0)
        print(f"\n[V] Found {subdomain_count} subdomains")
    
    # 7. Surface diff
    print_header("7. SURFACE DIFF (Change Detection)")
    diff = client.surface_diff(snapshot_id)
    print_json(diff)
    
    # Summary
    print_header("SCAN SUMMARY")
    print(f"Target IP:        {args.target}")
    print(f"Snapshot ID:      {snapshot_id}")
    print(f"Status:           {findings.get('status')}")
    print(f"Findings:         {findings_count} ports")
    if args.subdomains:
        print(f"Subdomains:       {subdomain_count}")
    print(f"Timestamp:        {findings.get('created_at')}")
    
    # Severity breakdown
    summary = findings.get("summary", {})
    by_severity = summary.get("by_severity", {})
    print(f"\nSeverity Breakdown:")
    print(f"  CRITICA:  {by_severity.get('CRITICA', 0)}")
    print(f"  ALTA:     {by_severity.get('ALTA', 0)}")
    print(f"  MEDIA:    {by_severity.get('MEDIA', 0)}")
    
    print("\n[V] Test completed successfully!")

if __name__ == "__main__":
    main()
