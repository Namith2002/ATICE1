# services/backend/app/store.py
"""
Advanced IOC Store with threat scoring, correlation engine, and analysis
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from uuid import uuid4
from copy import deepcopy
from difflib import SequenceMatcher
from enum import Enum

DATA_PATH_DEFAULT = "backend/app/data/iocs.json"

class ThreatLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class CorrelationEngine:
    """Advanced correlation analysis engine."""
    
    def __init__(self, store):
        self.store = store
    
    def detect_clusters(self, nodes: List[Dict], edges: List[Dict]) -> int:
        """Detect number of clusters using simple clustering."""
        if not nodes:
            return 0
        
        visited = set()
        clusters = 0
        adj_list = {n["id"]: [] for n in nodes}
        
        for edge in edges:
            # Only add edges if both nodes exist in the node list
            if edge["from"] in adj_list and edge["to"] in adj_list:
                adj_list[edge["from"]].append(edge["to"])
                adj_list[edge["to"]].append(edge["from"])
        
        def dfs(node_id):
            visited.add(node_id)
            for neighbor in adj_list.get(node_id, []):
                if neighbor not in visited:
                    dfs(neighbor)
        
        for node in nodes:
            if node["id"] not in visited:
                dfs(node["id"])
                clusters += 1
        
        return clusters
    
    def get_related_iocs(self, ioc_id: str, min_score: float = 0.5) -> List[Dict]:
        """Get IOCs related to a specific IOC."""
        related = []
        edges = self.store.compute_correlations(threshold=min_score)
        
        for edge in edges:
            if edge["from"] == ioc_id:
                related.append(self.store.get_ioc(edge["to"]))
            elif edge["to"] == ioc_id:
                related.append(self.store.get_ioc(edge["from"]))
        
        return [r for r in related if r is not None]

class IOCStore:
    """Advanced IOC storage with caching and correlation analysis."""
    
    def __init__(self, path=DATA_PATH_DEFAULT):
        self.path = Path(path)
        self._data: Dict[str, Dict] = {}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._load()
        self.correlation_engine = CorrelationEngine(self)

    def _load(self):
        """Load IOCs from JSON file."""
        if self.path.exists():
            try:
                with self.path.open("r", encoding="utf-8") as f:
                    arr = json.load(f)
                    self._data = {item["id"]: item for item in arr}
            except Exception as e:
                print(f"Error loading data: {e}")
                self._data = {}
        else:
            self._data = {}

    def _persist(self):
        with self.path.open("w", encoding="utf-8") as f:
            json.dump(list(self._data.values()), f, default=str, indent=2)

    def _now(self) -> str:
        """Get current UTC timestamp."""
        return datetime.utcnow().isoformat() + "Z"

    def score_to_threat_level(self, score: float) -> str:
        """Convert numerical score to threat level."""
        if score >= 90:
            return ThreatLevel.CRITICAL.value
        elif score >= 70:
            return ThreatLevel.HIGH.value
        elif score >= 50:
            return ThreatLevel.MEDIUM.value
        elif score >= 30:
            return ThreatLevel.LOW.value
        else:
            return ThreatLevel.INFO.value

    def _score(self, item: Dict) -> float:
        """
        Advanced threat scoring algorithm.
        Factors: type, frequency, metadata indicators, confidence, detections
        """
        base = 10.0
        t = item.get("type", "").lower()
        
        # Type-based scoring
        type_scores = {
            "cve": 85.0,
            "hash": 70.0,
            "url": 65.0,
            "ip": 55.0,
            "domain": 50.0,
            "email": 40.0,
            "file": 60.0
        }
        base = type_scores.get(t, 10.0)
        
        # Description-based indicators
        desc = (item.get("description", "") or "").lower()
        keywords = {
            "ransomware": 25,
            "malware": 20,
            "trojan": 20,
            "botnet": 25,
            "command_control": 30,
            "exploit": 15,
            "phishing": 15,
            "worm": 20,
            "backdoor": 25,
        }
        
        for keyword, bonus in keywords.items():
            if keyword in desc:
                base += bonus
        
        # Metadata-based scoring
        metadata = item.get("metadata", {})
        
        # Detection count
        detections = int(metadata.get("detection_count", 0))
        base += min(detections * 2, 30)  # Cap at 30 points
        
        # Source reputation
        source_scores = {
            "virustotal": 10,
            "abuseipdb": 8,
            "alienvault": 8,
            "internal": 5,
            "manual": 2
        }
        source = item.get("source", "manual").lower()
        base += source_scores.get(source, 3)
        
        # Confidence modifier
        confidence = item.get("confidence", 0.5)
        base *= confidence
        
        # Frequency boost
        seen_count = int(metadata.get("seen_count", 1))
        base += min(seen_count * 1.5, 15)
        
        # Clamp and return
        return round(max(0, min(100, base)), 2)

    def create_or_update_ioc(self, payload: Dict) -> Dict:
        """Create new IOC or update existing one."""
        found_id = None
        for _id, item in self._data.items():
            if item["type"] == payload["type"] and item["value"] == payload["value"]:
                found_id = _id
                break

        if found_id:
            # Update existing
            item = self._data[found_id]
            item["last_seen"] = self._now()
            item.setdefault("metadata", {}).update(payload.get("metadata", {}))
            item["source"] = payload.get("source", item.get("source"))
            if payload.get("description"):
                item["description"] = payload.get("description")
            if "confidence" in payload:
                item["confidence"] = payload["confidence"]
            item["score"] = self._score(item)
            item["detections"] = item.get("metadata", {}).get("detection_count", 0)
            self._persist()
            return deepcopy(item)

        # Create new
        new_id = str(uuid4())
        now = self._now()
        item = {
            "id": new_id,
            "type": payload["type"],
            "value": payload["value"],
            "source": payload.get("source", "manual"),
            "description": payload.get("description", ""),
            "confidence": payload.get("confidence", 0.5),
            "metadata": payload.get("metadata", {}),
            "first_seen": now,
            "last_seen": now,
            "detections": 0,
        }
        item["score"] = self._score(item)
        self._data[new_id] = item
        self._persist()
        return deepcopy(item)

    def update_ioc(self, ioc_id: str, updates: Dict) -> Dict:
        """Update an existing IOC."""
        if ioc_id not in self._data:
            return None
        
        item = self._data[ioc_id]
        item["last_seen"] = self._now()
        
        if "description" in updates:
            item["description"] = updates["description"]
        if "metadata" in updates and updates["metadata"]:
            item["metadata"].update(updates["metadata"])
        if "confidence" in updates:
            item["confidence"] = updates["confidence"]
        
        item["score"] = self._score(item)
        self._persist()
        return deepcopy(item)

    def delete_ioc(self, ioc_id: str) -> bool:
        """Delete an IOC."""
        if ioc_id in self._data:
            del self._data[ioc_id]
            self._persist()
            return True
        return False

    def list_iocs(self, skip: int = 0, limit: int = 50) -> List[Dict]:
        """List IOCs with pagination."""
        items = [deepcopy(v) for v in self._data.values()]
        items.sort(key=lambda x: x["last_seen"], reverse=True)
        return items[skip:skip + limit]

    def get_ioc(self, ioc_id: str) -> Optional[Dict]:
        """Get a specific IOC."""
        v = self._data.get(ioc_id)
        return deepcopy(v) if v else None

    def search_iocs(self, query: str) -> List[Dict]:
        """Search IOCs by value or type."""
        query_lower = query.lower()
        results = []
        
        for item in self._data.values():
            if query_lower in item["value"].lower() or query_lower == item["type"]:
                results.append(deepcopy(item))
        
        # Sort by score
        results.sort(key=lambda x: x["score"], reverse=True)
        return results[:50]

    def compute_correlations(self, threshold: float = 0.5) -> List[Dict]:
        """
        Compute correlations between IOCs with advanced heuristics.
        """
        edges = []
        items = list(self._data.values())
        n = len(items)
        
        for i in range(n):
            a = items[i]
            for j in range(i + 1, n):
                b = items[j]
                score = self._correlation_score(a, b)
                if score >= threshold:
                    edges.append({
                        "from": a["id"],
                        "to": b["id"],
                        "score": round(score, 3),
                        "type": self._correlation_type(a, b)
                    })
        
        return edges

    def _correlation_type(self, a: Dict, b: Dict) -> str:
        """Determine correlation type."""
        if a["value"] == b["value"]:
            return "exact_match"
        if a["type"] == b["type"]:
            return "same_type"
        if a.get("source") == b.get("source"):
            return "same_source"
        return "similarity"

    def _similarity(self, s1: str, s2: str) -> float:
        if not s1 or not s2:
            return 0.0
        return SequenceMatcher(None, s1, s2).ratio()

    def _correlation_score(self, a: Dict, b: Dict) -> float:
        """Calculate correlation score between two IOCs."""
        # Exact match
        if a["value"] == b["value"]:
            return 1.0
        
        # CVE correlation
        if a["type"] == "cve" and b["type"] == "cve":
            if a["value"].split(":")[-1] == b["value"].split(":")[-1]:
                return 1.0
        
        # Domain/URL domain sharing
        if a["type"] in ("domain", "url") and b["type"] in ("domain", "url"):
            a_val = a["value"].split("/")[-1].lower()
            b_val = b["value"].split("/")[-1].lower()
            if a_val in b_val or b_val in a_val:
                return 0.85
        
        # Hash prefix matching (potential variant detection)
        if a["type"] == "hash" and b["type"] == "hash":
            if len(a["value"]) > 8 and len(b["value"]) > 8:
                if a["value"][:16] == b["value"][:16]:
                    return 0.8
                if a["value"][:8] == b["value"][:8]:
                    return 0.6
        
        # Email domain matching
        if a["type"] == "email" and b["type"] == "email":
            a_domain = a["value"].split("@")[-1].lower()
            b_domain = b["value"].split("@")[-1].lower()
            if a_domain == b_domain:
                return 0.7
        
        # IP and domain correlation
        if (a["type"] == "ip" and b["type"] == "domain") or \
           (a["type"] == "domain" and b["type"] == "ip"):
            # Would need DNS data in production
            return 0.0
        
        # General string similarity
        sim = self._similarity(a["value"], b["value"])
        
        # Boost for same source
        if a.get("source") == b.get("source") and a.get("source") not in ("manual", ""):
            sim = min(1.0, sim + 0.15)
        
        # Boost for high confidence indicators
        confidence_boost = ((a.get("confidence", 0.5) + b.get("confidence", 0.5)) / 2) * 0.1
        sim = min(1.0, sim + confidence_boost)
        
        return round(sim, 3)

    def generate_threat_analysis(self, iocs: List[Dict]) -> Dict:
        """Generate comprehensive threat analysis."""
        if not iocs:
            return {
                "total_iocs": 0,
                "critical_threats": 0,
                "high_threats": 0,
                "medium_threats": 0,
                "low_threats": 0,
                "average_score": 0,
                "top_sources": {}
            }
        
        threat_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }
        
        source_counts = {}
        total_score = 0
        
        for ioc in iocs:
            score = ioc["score"]
            total_score += score
            threat_level = self.score_to_threat_level(score)
            threat_counts[threat_level] += 1
            
            source = ioc.get("source", "unknown")
            source_counts[source] = source_counts.get(source, 0) + 1
        
        # Sort sources by count
        top_sources = dict(sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:10])
        
        return {
            "total_iocs": len(iocs),
            "critical_threats": threat_counts["CRITICAL"],
            "high_threats": threat_counts["HIGH"],
            "medium_threats": threat_counts["MEDIUM"],
            "low_threats": threat_counts["LOW"],
            "average_score": round(total_score / len(iocs), 2),
            "top_sources": top_sources
        }
