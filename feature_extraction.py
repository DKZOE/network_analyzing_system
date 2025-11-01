#!/usr/bin/env python3
"""
feature_extraction.py
Converts PCAP files to session-level JSON with extracted features.
"""

import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict
import ipaddress

def run_tshark(pcap_file):
    """Convert PCAP to JSON using tshark."""
    try:
        result = subprocess.run(
            ["tshark", "-r", str(pcap_file), "-T", "json"],
            capture_output=True,
            text=True,
            check=True
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error running tshark: {e}", file=sys.stderr)
        return []
    except json.JSONDecodeError as e:
        print(f"Error parsing tshark JSON: {e}", file=sys.stderr)
        return []

def extract_packet_info(packet):
    """Extract relevant fields from a tshark packet."""
    layers = packet.get("_source", {}).get("layers", {})
    
    # Frame info
    frame = layers.get("frame", {})
    time_epoch = frame.get("frame.time_epoch")
    time_str = frame.get("frame.time")
    frame_len = int(frame.get("frame.len", 0) or 0)

    if time_epoch is not None:
        try:
            timestamp = float(time_epoch)
        except ValueError:
            timestamp = 0.0
    elif time_str:
        try:
            dt = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
            timestamp = dt.timestamp()
        except Exception:
            timestamp = 0.0
    else:
        timestamp = 0.0
    
    # IP layer
    ip = layers.get("ip", {})
    src_ip = ip.get("ip.src", "0.0.0.0")
    dst_ip = ip.get("ip.dst", "0.0.0.0")
    
    # Transport layer
    tcp = layers.get("tcp", {})
    udp = layers.get("udp", {})
    
    src_port = tcp.get("tcp.srcport") or udp.get("udp.srcport", "0")
    dst_port = tcp.get("tcp.dstport") or udp.get("udp.dstport", "0")
    
    return {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": str(src_port),
        "dst_port": str(dst_port),
        "bytes": frame_len
    }

def build_sessions(packets):
    """Group packets into sessions based on 5-tuple."""
    sessions = defaultdict(list)
    
    for pkt in packets:
        info = extract_packet_info(pkt)
        
        # Create session key (bidirectional)
        key1 = (info["src_ip"], info["dst_ip"], info["src_port"], info["dst_port"])
        key2 = (info["dst_ip"], info["src_ip"], info["dst_port"], info["src_port"])
        
        # Use consistent key ordering
        session_key = tuple(sorted([key1, key2])[0])
        sessions[session_key].append(info)
    
    return sessions

def calculate_unique_destinations(all_sessions, current_session_key, window_minutes=10):
    """Calculate unique destination count in sliding time window."""
    current_packets = all_sessions[current_session_key]
    if not current_packets:
        return 0
    
    latest_time = max(p["timestamp"] for p in current_packets)
    window_start = latest_time - (window_minutes * 60)
    
    src_ip = current_session_key[0]
    destinations = set()
    
    for session_key, packets in all_sessions.items():
        if session_key[0] == src_ip:  # Same source IP
            for pkt in packets:
                if window_start <= pkt["timestamp"] <= latest_time:
                    destinations.add(session_key[1])  # Add destination IP
    
    return len(destinations)

def extract_features(sessions):
    """Extract numeric features from sessions."""
    features_list = []
    
    for session_key, packets in sessions.items():
        if not packets:
            continue
        
        timestamps = [p["timestamp"] for p in packets]
        duration = max(timestamps) - min(timestamps)
        total_bytes = sum(p["bytes"] for p in packets)
        packet_count = len(packets)
        packets_per_second = packet_count / duration if duration > 0 else packet_count
        
        unique_dest_count = calculate_unique_destinations(sessions, session_key)
        
        features = {
            "src_ip": session_key[0],
            "dst_ip": session_key[1],
            "src_port": session_key[2],
            "dst_port": session_key[3],
            "duration": round(duration, 3),
            "total_bytes": total_bytes,
            "packet_count": packet_count,
            "packets_per_second": round(packets_per_second, 3),
            "unique_destination_count": unique_dest_count,
            "first_seen": datetime.fromtimestamp(min(timestamps)).isoformat(),
            "last_seen": datetime.fromtimestamp(max(timestamps)).isoformat()
        }
        
        features_list.append(features)
    
    return features_list

def main(pcap_file, output_file):
    """Main extraction pipeline."""
    print(f"Processing {pcap_file}...")
    
    # Convert PCAP to JSON
    packets = run_tshark(pcap_file)
    
    if not packets:
        print("No packets extracted.", file=sys.stderr)
        return
    
    print(f"Extracted {len(packets)} packets")
    
    # Build sessions
    sessions = build_sessions(packets)
    print(f"Built {len(sessions)} sessions")
    
    # Extract features
    features = extract_features(sessions)
    print(f"Extracted features for {len(features)} sessions")
    
    # Save to JSON
    with open(output_file, 'w') as f:
        json.dump(features, f, indent=2)
    
    print(f"Saved to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python feature_extraction.py <input.pcap> <output.json>")
        sys.exit(1)
    
    main(sys.argv[1], sys.argv[2])