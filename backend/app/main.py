# services/backend/app/main.py
"""
ATICE Advanced Backend API
Threat Intelligence Correlation Engine with Authentication & Caching
"""

from fastapi import FastAPI, HTTPException, Depends, status, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
from uuid import uuid4
from datetime import datetime, timedelta
import logging
import json
from functools import lru_cache

from .store import IOCStore, ThreatLevel, CorrelationEngine
from .auth import create_access_token, verify_token, get_current_user
from .cache import CacheManager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI with advanced configuration
app = FastAPI(
    title="ATICE Advanced - Threat Intelligence API",
    description="Advanced IOC correlation and threat scoring engine",
    version="2.0.0",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize services
store = IOCStore("services/backend/app/data/iocs.json")
cache = CacheManager(ttl=300)  # 5 minute cache
correlation_engine = CorrelationEngine(store)

# ============================================================================
# Helper Functions
# ============================================================================

def enrich_ioc_with_threat_level(ioc: Dict[str, Any]) -> Dict[str, Any]:
    """Add threat_level to IOC based on its score."""
    ioc["threat_level"] = store.score_to_threat_level(ioc.get("score", 0))
    
    # Ensure datetime fields are in proper format
    if isinstance(ioc.get("first_seen"), str):
        ioc["first_seen"] = datetime.fromisoformat(ioc["first_seen"].replace("Z", "+00:00"))
    if isinstance(ioc.get("last_seen"), str):
        ioc["last_seen"] = datetime.fromisoformat(ioc["last_seen"].replace("Z", "+00:00"))
    
    return ioc

# ============================================================================
# Pydantic Models
# ============================================================================

class IOC(BaseModel):
    type: str = Field(..., description="ip|domain|url|hash|cve|email|file")
    value: str = Field(..., min_length=1)
    source: Optional[str] = "manual"
    description: Optional[str] = ""
    metadata: Optional[Dict[str, Any]] = {}
    confidence: Optional[float] = Field(default=0.5, ge=0.0, le=1.0)
    
    @validator('type')
    def validate_type(cls, v):
        valid_types = ["ip", "domain", "url", "hash", "cve", "email", "file"]
        if v.lower() not in valid_types:
            raise ValueError(f"Type must be one of {valid_types}")
        return v.lower()

class IOCOut(IOC):
    id: str
    first_seen: datetime
    last_seen: datetime
    score: float
    threat_level: str
    detections: int
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

class IOCBatch(BaseModel):
    iocs: List[IOC]
    source: Optional[str] = "batch_import"

class IOCUpdate(BaseModel):
    description: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    confidence: Optional[float] = None

class CorrelationResponse(BaseModel):
    nodes: List[IOCOut]
    edges: List[Dict]
    summary: Dict[str, Any]

class ThreatAnalysis(BaseModel):
    total_iocs: int
    critical_threats: int
    high_threats: int
    medium_threats: int
    low_threats: int
    average_score: float
    top_sources: Dict[str, int]

class HealthResponse(BaseModel):
    status: str
    timestamp: datetime
    version: str
    cache_size: int
    ioc_count: int

# ============================================================================
# Authentication & Security
# ============================================================================

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int

@app.post("/api/v1/auth/login", response_model=TokenResponse)
def login(credentials: LoginRequest):
    """Authenticate and get JWT token."""
    # Simple validation (in production use proper credential verification)
    if credentials.username == "admin" and credentials.password == "admin":
        token = create_access_token(
            data={"sub": credentials.username},
            expires_delta=timedelta(hours=24)
        )
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": 86400
        }
    raise HTTPException(status_code=401, detail="Invalid credentials")

# ============================================================================
# IOC Endpoints
# ============================================================================

@app.post("/api/v1/iocs", response_model=IOCOut, tags=["IOCs"])
def ingest_ioc(ioc: IOC, current_user: str = Depends(get_current_user)):
    """Ingest a new IOC or update existing one."""
    logger.info(f"Ingesting IOC: {ioc.type}:{ioc.value}")
    created = store.create_or_update_ioc(ioc.dict())
    cache.invalidate_pattern("ioc_*")
    return created

@app.post("/api/v1/iocs/batch", response_model=List[IOCOut], tags=["IOCs"])
def ingest_batch(batch: IOCBatch, current_user: str = Depends(get_current_user)):
    """Batch ingest multiple IOCs."""
    logger.info(f"Batch ingesting {len(batch.iocs)} IOCs")
    results = []
    for ioc_data in batch.iocs:
        ioc_dict = ioc_data.dict()
        ioc_dict["source"] = batch.source
        ioc = store.create_or_update_ioc(ioc_dict)
        results.append(enrich_ioc_with_threat_level(ioc))
    cache.invalidate_pattern("ioc_*")
    return results

@app.get("/api/v1/iocs", response_model=List[IOCOut], tags=["IOCs"])
def list_iocs(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=10000),
    type_filter: Optional[str] = Query(None),
    threat_level: Optional[str] = Query(None),
    current_user: str = Depends(get_current_user)
):
    """List all IOCs with optional filtering."""
    iocs = store.list_iocs(skip=skip, limit=limit)
    
    if type_filter:
        iocs = [i for i in iocs if i["type"] == type_filter.lower()]
    
    if threat_level:
        iocs = [i for i in iocs if store.score_to_threat_level(i["score"]) == threat_level]
    
    iocs = [enrich_ioc_with_threat_level(i) for i in iocs]
    return iocs

@app.get("/api/v1/iocs/{ioc_id}", response_model=IOCOut, tags=["IOCs"])
def get_ioc(ioc_id: str, current_user: str = Depends(get_current_user)):
    """Get a specific IOC by ID."""
    item = store.get_ioc(ioc_id)
    if not item:
        raise HTTPException(status_code=404, detail="IOC not found")
    
    item = enrich_ioc_with_threat_level(item)
    return item

@app.patch("/api/v1/iocs/{ioc_id}", response_model=IOCOut, tags=["IOCs"])
def update_ioc(
    ioc_id: str,
    update: IOCUpdate,
    current_user: str = Depends(get_current_user)
):
    """Update an existing IOC."""
    item = store.get_ioc(ioc_id)
    if not item:
        raise HTTPException(status_code=404, detail="IOC not found")
    
    updated = store.update_ioc(ioc_id, update.dict(exclude_unset=True))
    cache.invalidate_pattern(f"ioc_{ioc_id}")
    return enrich_ioc_with_threat_level(updated)

@app.delete("/api/v1/iocs/{ioc_id}", tags=["IOCs"])
def delete_ioc(ioc_id: str, current_user: str = Depends(get_current_user)):
    """Delete an IOC."""
    success = store.delete_ioc(ioc_id)
    if not success:
        raise HTTPException(status_code=404, detail="IOC not found")
    cache.invalidate_pattern(f"ioc_{ioc_id}")
    return {"message": "IOC deleted successfully"}

# ============================================================================
# Analysis & Correlation Endpoints
# ============================================================================

@app.get("/api/v1/correlations", response_model=CorrelationResponse, tags=["Analysis"])
def correlations(
    threshold: float = Query(0.5, ge=0.0, le=1.0),
    current_user: str = Depends(get_current_user)
):
    """Return correlations between IOCs."""
    edges = store.compute_correlations(threshold=threshold)
    nodes = store.list_iocs()
    nodes = [enrich_ioc_with_threat_level(n) for n in nodes]
    
    # Calculate summary
    summary = {
        "total_edges": len(edges),
        "total_nodes": len(nodes),
        "avg_score": sum(e["score"] for e in edges) / len(edges) if edges else 0,
        "clusters": correlation_engine.detect_clusters(nodes, edges)
    }
    
    result = {
        "nodes": nodes,
        "edges": edges,
        "summary": summary
    }
    
    return result

@app.post("/api/v1/analyze", response_model=ThreatAnalysis, tags=["Analysis"])
def analyze_threats(current_user: str = Depends(get_current_user)):
    """Comprehensive threat analysis."""
    cache_key = "threat_analysis"
    cached = cache.get(cache_key)
    if cached:
        return cached
    
    iocs = store.list_iocs()
    analysis = store.generate_threat_analysis(iocs)
    cache.set(cache_key, analysis)
    return analysis

@app.post("/api/v1/search", response_model=List[IOCOut], tags=["Search"])
def search_iocs(
    query: str = Query(..., min_length=1),
    current_user: str = Depends(get_current_user)
):
    """Search IOCs by value."""
    results = store.search_iocs(query)
    return [enrich_ioc_with_threat_level(r) for r in results]

@app.get("/api/v1/score/{ioc_id}", tags=["Scoring"])
def score_ioc(ioc_id: str, current_user: str = Depends(get_current_user)):
    """Get threat score for an IOC."""
    item = store.get_ioc(ioc_id)
    if not item:
        raise HTTPException(status_code=404, detail="IOC not found")
    
    threat_level = store.score_to_threat_level(item["score"])
    return {
        "id": ioc_id,
        "score": item["score"],
        "threat_level": threat_level,
        "detections": item.get("detections", 0),
        "confidence": item.get("confidence", 0.5)
    }

# ============================================================================
# System & Monitoring Endpoints
# ============================================================================

@app.get("/api/v1/health", response_model=HealthResponse, tags=["System"])
def health_check():
    """System health check."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow(),
        "version": "2.0.0",
        "cache_size": len(cache._cache),
        "ioc_count": len(store.list_iocs())
    }

@app.get("/api/v1/stats", tags=["System"])
def get_stats(current_user: str = Depends(get_current_user)):
    """Get system statistics."""
    iocs = store.list_iocs()
    sources = {}
    types_count = {}
    
    for ioc in iocs:
        source = ioc.get("source", "unknown")
        sources[source] = sources.get(source, 0) + 1
        
        ioc_type = ioc.get("type", "unknown")
        types_count[ioc_type] = types_count.get(ioc_type, 0) + 1
    
    return {
        "total_iocs": len(iocs),
        "by_source": sources,
        "by_type": types_count,
        "avg_score": sum(i["score"] for i in iocs) / len(iocs) if iocs else 0,
        "cache_entries": len(cache._cache),
        "timestamp": datetime.utcnow()
    }

@app.get("/api/v1/export", tags=["Export"])
def export_iocs(
    format: str = Query("json", regex="^(json|csv)$"),
    current_user: str = Depends(get_current_user)
):
    """Export all IOCs in specified format."""
    iocs = store.list_iocs()
    
    if format == "json":
        return {"data": iocs, "format": "json", "count": len(iocs)}
    
    elif format == "csv":
        # Return CSV content
        import io
        output = io.StringIO()
        if iocs:
            fieldnames = ["id", "type", "value", "score", "source", "first_seen"]
            output.write(",".join(fieldnames) + "\n")
            for ioc in iocs:
                row = [
                    ioc.get("id", ""),
                    ioc.get("type", ""),
                    ioc.get("value", ""),
                    str(ioc.get("score", "")),
                    ioc.get("source", ""),
                    ioc.get("first_seen", "")
                ]
                output.write(",".join(f'"{v}"' for v in row) + "\n")
        
        return {
            "data": output.getvalue(),
            "format": "csv",
            "count": len(iocs)
        }

# ============================================================================
# Error Handlers
# ============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "status_code": exc.status_code,
            "timestamp": datetime.utcnow().isoformat()
        }
    )

@app.exception_handler(ValueError)
async def value_error_handler(request, exc):
    return JSONResponse(
        status_code=400,
        content={
            "detail": str(exc),
            "status_code": 400,
            "timestamp": datetime.utcnow().isoformat()
        }
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
