#!/usr/bin/env python3
"""
Timeline Generator Script
Generate forensic timeline dari multiple artifact sources
Author: Dina Permata (Toolsmith)
Date: 2025-11-15
"""

import csv
import json
from datetime import datetime
from pathlib import Path

class TimelineGenerator:
    def __init__(self, output_file):
        self.output_file = output_file
        self.events = []
    
    def add_event(self, timestamp, source, event_type, user, hostname, 
                  description, filename="N/A", inode="N/A", notes=""):
        """Add event ke timeline"""
        self.events.append({
            'timestamp': timestamp,
            'source': source,
            'type': event_type,
            'user': user,
            'hostname': hostname,
            'description': description,
            'filename': filename,
            'inode': inode,
            'notes': notes
        })
    
    def parse_registry_timeline(self, registry_path):
        """Parse registry artifacts untuk timeline"""
        print(f"[+] Parsing registry from {registry_path}")
        
        # Simulated registry parsing
        # In real scenario, use python-registry or Registry Explorer output
        
        self.add_event(
            timestamp="2025-11-12T02:18:10+07:00",
            source="REGISTRY:NTUSER",
            event_type="Registry Modified",
            user="siti.rahma",
            hostname="FINANCE-WKS-07",
            description="Run key created for persistence",
            filename="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            notes="⚠️ PERSISTENCE ESTABLISHED"
        )
        
        print("  ✅ Registry timeline entries added")
    
    def parse_evtx_timeline(self, evtx_path):
        """Parse event logs untuk timeline"""
        print(f"[+] Parsing event logs from {evtx_path}")
        
        # Simulated EVTX parsing
        # In real scenario, use python-evtx or EvtxECmd output
        
        critical_events = [
            {
                'timestamp': "2025-11-12T02:13:47+07:00",
                'event_id': 4624,
                'description': "Network logon from 203.78.121.45",
                'notes': "⚠️ EARLIEST POINT OF COMPROMISE"
            },
            {
                'timestamp': "2025-11-12T02:22:33+07:00",
                'event_id': 7045,
                'description': "WindowsSecurityService installed",
                'notes': "⚠️ MALICIOUS SERVICE"
            },
            {
                'timestamp': "2025-11-12T06:49:05+07:00",
                'event_id': 1102,
                'description': "Security log partially cleared",
                'notes': "⚠️ ANTI-FORENSIC ACTIVITY"
            }
        ]
        
        for event in critical_events:
            self.add_event(
                timestamp=event['timestamp'],
                source=f"EVTX:Security",
                event_type=f"Event ID {event['event_id']}",
                user="siti.rahma",
                hostname="FINANCE-WKS-07",
                description=event['description'],
                notes=event['notes']
            )
        
        print("  ✅ Event log timeline entries added")
    
    def parse_prefetch_timeline(self, prefetch_path):
        """Parse prefetch files untuk timeline"""
        print(f"[+] Parsing prefetch from {prefetch_path}")
        
        # Simulated prefetch parsing
        # In real scenario, use PECmd output
        
        malicious_executables = [
            {
                'timestamp': "2025-11-12T02:16:45+07:00",
                'filename': "SECURITYUPDATE.EXE-A3B2C1D4.pf",
                'executable': "SecurityUpdate.exe",
                'run_count': 1
            },
            {
                'timestamp': "2025-11-12T02:22:45+07:00",
                'filename': "SVCHOST_ALT.EXE-5D6E7F8A.pf",
                'executable': "svchost_alt.exe",
                'run_count': 1
            }
        ]
        
        for pf in malicious_executables:
            self.add_event(
                timestamp=pf['timestamp'],
                source="PREFETCH",
                event_type="Program Execution",
                user="siti.rahma" if "SECURITY" in pf['executable'] else "SYSTEM",
                hostname="FINANCE-WKS-07",
                description=f"{pf['executable']} executed",
                filename=pf['filename'],
                notes=f"Run count: {pf['run_count']}"
            )
        
        print("  ✅ Prefetch timeline entries added")
    
    def parse_mft_timeline(self, mft_path):
        """Parse MFT untuk file system timeline"""
        print(f"[+] Parsing MFT from {mft_path}")
        
        # Simulated MFT parsing
        # In real scenario, use MFTECmd or analyzeMFT
        
        file_activities = [
            {
                'timestamp': "2025-11-12T02:15:22+07:00",
                'type': "File Created",
                'path': "C:\\Users\\siti.rahma\\AppData\\Local\\Temp\\SecurityUpdate.exe",
                'size': "5.2 MB",
                'inode': 23456
            },
            {
                'timestamp': "2025-11-12T02:18:45+07:00",
                'type': "File Created",
                'path': "C:\\Users\\siti.rahma\\AppData\\Roaming\\WindowsSecurity\\keylog.txt",
                'size': "0 bytes",
                'inode': 45678
            },
            {
                'timestamp': "2025-11-12T06:48:45+07:00",
                'type': "File Deleted",
                'path': "C:\\Users\\siti.rahma\\AppData\\Local\\Temp\\SecurityUpdate.exe",
                'size': "N/A",
                'inode': 23456
            }
        ]
        
        for file_act in file_activities:
            self.add_event(
                timestamp=file_act['timestamp'],
                source="NTFS:MFT",
                event_type=file_act['type'],
                user="siti.rahma",
                hostname="FINANCE-WKS-07",
                description=f"{file_act['type']}",
                filename=file_act['path'],
                inode=str(file_act['inode']),
                notes=f"Size: {file_act['size']}"
            )
        
        print("  ✅ MFT timeline entries added")
    
    def sort_timeline(self):
        """Sort events chronologically"""
        self.events.sort(key=lambda x: x['timestamp'])
    
    def export_csv(self):
        """Export timeline ke CSV"""
        print(f"\n[+] Exporting timeline to {self.output_file}")
        
        self.sort_timeline()
        
        with open(self.output_file, 'w', newline='', encoding='utf-8') as f:
            fieldnames = ['timestamp', 'source', 'type', 'user', 'hostname', 
                         'description', 'filename', 'inode', 'notes']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            
            writer.writeheader()
            for event in self.events:
                writer.writerow(event)
        
        print(f"  ✅ Exported {len(self.events)} events")
        print(f"  📄 File: {self.output_file}")
    
    def export_json(self, json_file):
        """Export timeline ke JSON format"""
        self.sort_timeline()
        
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(self.events, f, indent=2, ensure_ascii=False)
        
        print(f"  ✅ JSON export: {json_file}")
    
    def generate_summary_stats(self):
        """Generate summary statistics"""
        print("\n" + "="*60)
        print("TIMELINE SUMMARY STATISTICS")
        print("="*60)
        
        sources = {}
        for event in self.events:
            source = event['source']
            sources[source] = sources.get(source, 0) + 1
        
        print(f"\nTotal Events: {len(self.events)}")
        print("\nEvents by Source:")
        for source, count in sorted(sources.items()):
            print(f"  {source:20s}: {count:4d} events")
        
        # Time range
        if self.events:
            first = self.events[0]['timestamp']
            last = self.events[-1]['timestamp']
            print(f"\nTime Range:")
            print(f"  First Event: {first}")
            print(f"  Last Event:  {last}")
        
        print("="*60)

def main():
    print("="*60)
    print("FORENSIC TIMELINE GENERATOR")
    print("Case: FOR-2025-WKS-001")
    print("="*60)
    
    # Initialize timeline generator
    output_csv = "results/timeline/super_timeline.csv"
    output_json = "results/timeline/super_timeline.json"
    
    Path("results/timeline").mkdir(parents=True, exist_ok=True)
    
    timeline = TimelineGenerator(output_csv)
    
    # Parse different artifact sources
    print("\n[*] Parsing artifacts...")
    timeline.parse_registry_timeline("results/registry/")
    timeline.parse_evtx_timeline("results/evtx/")
    timeline.parse_prefetch_timeline("results/prefetch/")
    timeline.parse_mft_timeline("results/mft/")
    
    # Export timeline
    timeline.export_csv()
    timeline.export_json(output_json)
    
    # Generate stats
    timeline.generate_summary_stats()
    
    print("\n✅ Timeline generation complete!")

if __name__ == "__main__":
    main()