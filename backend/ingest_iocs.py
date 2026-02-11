#!/usr/bin/env python3
"""
IOC Batch Ingestion Script
Reads IOCs from a JSON file and ingests them via the API
"""

import json
import requests
import sys
from pathlib import Path
from typing import List, Dict, Any

# Configuration
API_BASE = "http://localhost:8000/api/v1"
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "admin123"
BATCH_SIZE = 10

def get_auth_token(username: str, password: str) -> str:
    """Authenticate and get access token."""
    response = requests.post(
        f"{API_BASE}/auth/login",
        json={"username": username, "password": password}
    )
    if response.status_code != 200:
        print(f"❌ Authentication failed: {response.text}")
        sys.exit(1)
    
    token = response.json().get("access_token")
    print(f"✅ Authentication successful")
    return token

def load_iocs(file_path: str) -> List[Dict[str, Any]]:
    """Load IOCs from JSON file."""
    path = Path(file_path)
    if not path.exists():
        print(f"❌ File not found: {file_path}")
        sys.exit(1)
    
    with open(path, 'r') as f:
        iocs = json.load(f)
    
    print(f"✅ Loaded {len(iocs)} IOCs from {file_path}")
    return iocs

def ingest_batch(iocs: List[Dict[str, Any]], token: str) -> bool:
    """Ingest a batch of IOCs via API."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "iocs": iocs,
        "source": "batch_import"
    }
    
    response = requests.post(
        f"{API_BASE}/iocs/batch",
        json=payload,
        headers=headers
    )
    
    if response.status_code == 200:
        result = response.json()
        print(f"✅ Successfully ingested {len(result)} IOCs")
        return True
    else:
        print(f"❌ Ingestion failed: {response.status_code}")
        print(f"   Response: {response.text}")
        return False

def main():
    """Main ingestion workflow."""
    print("=" * 60)
    print("ATICE IOC Batch Ingestion Tool")
    print("=" * 60)
    
    # Get file path from command line or use default
    if len(sys.argv) > 1:
        dataset_file = sys.argv[1]
    else:
        dataset_file = "dummy_iocs_dataset.json"
    
    # Get credentials
    username = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_USERNAME
    password = sys.argv[3] if len(sys.argv) > 3 else DEFAULT_PASSWORD
    
    print(f"\n📋 Configuration:")
    print(f"   API Base: {API_BASE}")
    print(f"   Dataset: {dataset_file}")
    print(f"   Username: {username}")
    
    # Authenticate
    print(f"\n🔐 Authenticating...")
    token = get_auth_token(username, password)
    
    # Load IOCs
    print(f"\n📂 Loading IOCs...")
    iocs = load_iocs(dataset_file)
    
    # Ingest in batches
    print(f"\n📤 Ingesting IOCs in batches of {BATCH_SIZE}...")
    total_ingested = 0
    
    for i in range(0, len(iocs), BATCH_SIZE):
        batch = iocs[i:i+BATCH_SIZE]
        batch_num = (i // BATCH_SIZE) + 1
        total_batches = (len(iocs) + BATCH_SIZE - 1) // BATCH_SIZE
        
        print(f"\n   Batch {batch_num}/{total_batches} ({len(batch)} IOCs)...")
        if ingest_batch(batch, token):
            total_ingested += len(batch)
    
    # Summary
    print(f"\n" + "=" * 60)
    print(f"✅ Ingestion Complete!")
    print(f"   Total IOCs ingested: {total_ingested}/{len(iocs)}")
    print(f"   Success rate: {(total_ingested/len(iocs)*100):.1f}%")
    print("=" * 60)

if __name__ == "__main__":
    main()
