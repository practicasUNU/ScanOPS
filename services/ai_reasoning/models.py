from pydantic import BaseModel, Field
from typing import Optional, List, Dict
from datetime import datetime

class Finding(BaseModel):
    """Hallazgo emitido por M3"""
    scan_id: str
    asset_id: int
    finding_id: str
    title: str
    description: str
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    cvss: float = Field(ge=0.0, le=10.0)
    cwe: Optional[str] = None
    detected_at: datetime
    scanner: str  # "nuclei", "zap", "openvas"
    
    class Config:
        extra = "allow"  # Permitir campos extras

class AIAnalysis(BaseModel):
    """Análisis realizado por M8"""
    finding_id: str
    is_false_positive: bool
    confidence: float = Field(ge=0.0, le=1.0)
    priority_score: float = Field(ge=0.0, le=10.0)
    ens_articles: List[str]  # ["Art. 5.1.6", "Art. 6.2.1"]
    recommended_action: str
    analysis_text: str
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)

class ProcessingResult(BaseModel):
    """Resultado de procesamiento de hallazgo"""
    finding_id: str
    status: str  # "success", "error", "skipped"
    analysis: Optional[AIAnalysis] = None
    error: Optional[str] = None
    processed_at: datetime = Field(default_factory=datetime.utcnow)

class FilterResult(BaseModel):
    """Resultado del filtrado de falsos positivos"""
    finding_id: str
    is_false_positive: bool
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str
    filter_method: str  # "rules", "ai_analysis", "confidence_score"
    status: str  # "passed" (real) o "rejected" (FP)
    filtered_at: datetime = Field(default_factory=datetime.utcnow)

class PriorityResult(BaseModel):
    """Resultado de priorización"""
    finding_id: str
    priority_score: float = Field(ge=0.0, le=10.0)
    rank: int
    factors: Dict[str, float]
    prioritized_at: datetime = Field(default_factory=datetime.utcnow)

class ENSMappingResult(BaseModel):
    """Resultado del mapeo a RD 311/2022"""
    finding_id: str
    ens_articles: List[str]  # ["Art. 5.1.6", "Art. 6.2.1"]
    compliance_status: str  # "COMPLIANT", "NOT_COMPLIANT", "UNKNOWN"
    risk_level: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    mapped_by: List[str]  # ["cwe_mapping", "ai_analysis"]
    mapped_at: datetime = Field(default_factory=datetime.utcnow)
