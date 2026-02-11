#!/usr/bin/env python3
"""
Direct IOC Ingestion Script
Directly writes IOCs to the data store, bypassing API
"""

import json
from pathlib import Path
from uuid import uuid4
from datetime import datetime

def generate_ioc_with_id(ioc_data):
    """Add ID and timestamps to an IOC."""
    now = datetime.utcnow().isoformat() + "Z"
    return {
        "id": str(uuid4()),
        "type": ioc_data["type"],
        "value": ioc_data["value"],
        "source": ioc_data.get("source", "batch_import"),
        "description": ioc_data.get("description", ""),
        "confidence": ioc_data.get("confidence", 0.5),
        "metadata": ioc_data.get("metadata", {}),
        "first_seen": now,
        "last_seen": now,
        "detections": ioc_data.get("metadata", {}).get("detection_count", 0),
        "score": calculate_score(ioc_data)
    }

def calculate_score(ioc_data):
    """Calculate threat score based on IOC data."""
    base = 10.0
    ioc_type = ioc_data.get("type", "").lower()
    
    type_scores = {
        "cve": 85.0,
        "hash": 70.0,
        "url": 65.0,
        "ip": 55.0,
        "domain": 50.0,
        "email": 40.0,
        "file": 60.0
    }
    base = type_scores.get(ioc_type, 10.0)
    
    # Description-based scoring
    desc = (ioc_data.get("description", "") or "").lower()
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
        "critical": 15,
        "remote code execution": 20,
        "privilege escalation": 12,
        "apt": 20
    }
    
    for keyword, bonus in keywords.items():
        if keyword in desc:
            base += bonus
    
    # Metadata-based scoring
    metadata = ioc_data.get("metadata", {})
    detections = int(metadata.get("detection_count", 0))
    base += min(detections * 0.1, 30)
    
    confidence = ioc_data.get("confidence", 0.5)
    base *= confidence
    
    seen_count = int(metadata.get("seen_count", 1))
    base += min(seen_count * 1.5, 15)
    
    return round(max(0, min(100, base)), 2)

def main():
    """Main ingestion workflow."""
    print("=" * 60)
    print("ATICE IOC Direct Ingestion Tool")
    print("=" * 60)
    
    dataset_file = Path("dummy_iocs_dataset.json")
    target_file = Path("services/backend/app/data/iocs.json")
    
    if not dataset_file.exists():
        print(f"❌ Dataset file not found: {dataset_file}")
        return
    
    # Load existing IOCs
    if target_file.exists():
        with open(target_file, 'r') as f:
            existing_iocs = json.load(f)
        print(f"📂 Loaded {len(existing_iocs)} existing IOCs")
    else:
        existing_iocs = []
        target_file.parent.mkdir(parents=True, exist_ok=True)
        print(f"📂 Creating new IOC store")
    
    # Load dataset
    with open(dataset_file, 'r') as f:
        dataset = json.load(f)
    
    print(f"📋 Loaded {len(dataset)} IOCs from dataset")
    
    # Process and add new IOCs
    print(f"\n📤 Ingesting IOCs...")
    for i, ioc_data in enumerate(dataset, 1):
        ioc = generate_ioc_with_id(ioc_data)
        existing_iocs.append(ioc)
        print(f"   ✅ {i}. {ioc_data['type']:8} {ioc_data['value'][:40]:40} | Score: {ioc['score']:.1f}")
    
    # Save to file
    with open(target_file, 'w') as f:
        json.dump(existing_iocs, f, indent=2)
    
    print(f"\n" + "=" * 60)
    print(f"✅ Ingestion Complete!")
    print(f"   Total IOCs in store: {len(existing_iocs)}")
    print(f"   File: {target_file}")
    print("=" * 60)

if __name__ == "__main__":
    main()
