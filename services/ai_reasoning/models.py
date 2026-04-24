from pydantic import BaseModel, Field
from typing import Optional, List
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
