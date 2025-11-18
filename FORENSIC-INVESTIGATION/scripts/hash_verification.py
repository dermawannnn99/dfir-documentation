#!/usr/bin/env python3
"""
Hash Verification Script
Verifikasi integritas evidence menggunakan multiple hash algorithms
"""

import hashlib
import sys
from pathlib import Path

def calculate_hash(filepath, algorithms=['md5', 'sha1', 'sha256']):
    """Calculate multiple hashes for a file"""
    
    hashes = {}
    hash_objects = {alg: getattr(hashlib, alg)() for alg in algorithms}
    
    print(f"\n📁 File: {filepath}")
    print(f"📊 Size: {Path(filepath).stat().st_size:,} bytes")
    print("\n🔐 Calculating hashes...")
    
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            for hash_obj in hash_objects.values():
                hash_obj.update(chunk)
    
    for alg, hash_obj in hash_objects.items():
        hashes[alg] = hash_obj.hexdigest()
        print(f"  {alg.upper()}: {hashes[alg]}")
    
    return hashes

def verify_hash(filepath, expected_hash, algorithm='sha256'):
    """Verify file hash matches expected value"""
    
    print(f"\n🔍 Verifying {algorithm.upper()} hash...")
    print(f"Expected: {expected_hash}")
    
    calculated = calculate_hash(filepath, [algorithm])[algorithm]
    print(f"Calculated: {calculated}")
    
    if calculated == expected_hash:
        print("✅ MATCH - Integrity verified!")
        return True
    else:
        print("❌ MISMATCH - File may be corrupted or tampered!")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python hash_verification.py <filepath> [expected_hash]")
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    if len(sys.argv) == 3:
        expected_hash = sys.argv[2]
        verify_hash(filepath, expected_hash)
    else:
        calculate_hash(filepath)