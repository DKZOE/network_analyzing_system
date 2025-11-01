# Network Security Monitoring Pipeline

An automated network traffic analysis system that captures packets, extracts features, trains ML models, and uses LLMs to identify security threats.

## Overview

This pipeline provides end-to-end network security monitoring:

1. **Packet Capture** - Continuously captures network traffic using `tcpdump`
2. **Feature Extraction** - Converts PCAP files to session-level features using `tshark`
3. **Anomaly Detection** - Trains and applies Isolation Forest ML model
4. **Threat Analysis** - Uses local LLMs (via Ollama) to classify and explain threats

## Architecture

```
Network Traffic → tcpdump → PCAP Files → tshark → Sessions JSON
                                              ↓
                                      Feature Extraction
                                              ↓
                                    Isolation Forest Model
                                              ↓
                                      Anomaly Scoring
                                              ↓
                                    LLM Analysis (Ollama)
                                              ↓
                                      Threat Reports
```

## Components

### 1. `feature_extraction.py`
Converts raw PCAP files into structured session data.

**What it does:**
- Parses PCAP files using `tshark` to extract packet-level data
- Groups packets into sessions based on 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol)
- Calculates session-level features:
  - `duration` - Session length in seconds
  - `total_bytes` - Total traffic volume
  - `packet_count` - Number of packets
  - `packets_per_second` - Traffic rate
  - `unique_destination_count` - Number of destinations contacted (for port scan detection)

**Usage:**
```bash
python3 feature_extraction.py input.pcap output.json
```

**Output format:**
```json
[
  {
    "src_ip": "192.168.1.100",
    "dst_ip": "8.8.8.8",
    "src_port": "54321",
    "dst_port": "443",
    "duration": 12.456,
    "total_bytes": 150000,
    "packet_count": 120,
    "packets_per_second": 9.63,
    "unique_destination_count": 3,
    "first_seen": "2025-11-01T10:30:00",
    "last_seen": "2025-11-01T10:30:12"
  }
]
```

### 2. `model_train.py`
Trains an Isolation Forest model for unsupervised anomaly detection.

**What it does:**
- Loads session features from JSON
- Normalizes features using StandardScaler
- Trains Isolation Forest model (optimized for anomaly detection)
- Saves trained model and scaler to pickle file

**Key parameters:**
- `contamination` - Expected proportion of anomalies (default: 0.1 = 10%)
- `n_estimators` - Number of trees (default: 100)

**Usage:**
```bash
# Train with default parameters
python3 model_train.py sessions.json model.pkl

# Train with custom contamination rate
python3 model_train.py sessions.json model.pkl 0.15
```

**Why Isolation Forest?**
- Works well with unlabeled data
- Fast training and inference
- Effective at detecting outliers in multi-dimensional feature spaces
- No need for historical attack data

### 3. `model_score.py`
Applies the trained model to score new sessions.

**What it does:**
- Loads trained model and scaler
- Normalizes session features
- Calculates anomaly scores (0-1 scale, higher = more anomalous)
- Flags sessions with binary anomaly indicator

**Usage:**
```bash
python3 model_score.py sessions.json scored.json model.pkl
```

**Output format:**
```json
[
  {
    "src_ip": "10.0.0.5",
    "dst_ip": "93.184.216.34",
    "anomaly_score": 0.852,
    "is_anomaly": 1,
    ...
  }
]
```

**Anomaly score interpretation:**
- `0.0 - 0.3` - Normal traffic
- `0.3 - 0.6` - Suspicious, monitor
- `0.6 - 1.0` - Highly anomalous, investigate

### 4. `analyze_with_ollama.py`
Uses local LLMs to provide human-readable threat analysis.

**What it does:**
- Filters sessions above anomaly threshold (default: 0.6)
- Sends each session to Ollama with specialized security prompt
- Extracts structured JSON responses with threat classification
- Parallelizes analysis using ThreadPoolExecutor (4 workers)
- Includes retry logic and timeout handling

**Key features:**
- **Concurrency** - Analyzes 4 sessions simultaneously for speed
- **Retry logic** - Automatically retries failed analyses (max 2 attempts)
- **Timeout handling** - Increases timeout on retry (30s → 90s → 150s)
- **JSON extraction** - Parses LLM output even if wrapped in markdown

**Usage:**
```bash
# Basic usage with defaults
python3 analyze_with_ollama.py scored.json analysis.json

# Custom threshold and model
python3 analyze_with_ollama.py scored.json analysis.json 0.7 llama3 60

# Arguments: <input> <output> [threshold] [model] [timeout]
```

**Supported models:**
- `qwen2:1.5b` - Fast, lightweight (default)
- `llama3` - Balanced performance
- `deepseek-r1` - Advanced reasoning
- `mistral` - Good accuracy

**Output format:**
```json
[
  {
    "timestamp": "2025-11-01T10:35:42",
    "session": { ... },
    "llm_analysis": {
      "status": "suspicious",
      "reason": "High packet rate to single destination suggests port scanning",
      "action": "iptables -A INPUT -s 10.0.0.5 -j DROP"
    },
    "analysis_time_seconds": 2.34
  }
]
```

**Prompt engineering:**
The system uses a specialized prompt that:
- Presents session data in concise format
- Requests strict JSON output only
- Asks for status classification (normal/suspicious)
- Requires actionable firewall/IDS rules
- Limits response verbosity for speed

### 5. `run_pipeline.sh`
Orchestrates the complete monitoring pipeline.

**What it does:**
- Manages dependencies and environment setup
- Controls packet capture lifecycle
- Monitors directory for new PCAP files
- Automatically processes new captures
- Handles model training and inference

**Commands:**

```bash
# Start full monitoring (capture + analysis)
./run_pipeline.sh monitor

# Start capture only
./run_pipeline.sh start

# Stop capture
./run_pipeline.sh stop

# Process single PCAP file
./run_pipeline.sh process file.pcap

# Train model from sessions JSON
./run_pipeline.sh train sessions.json
```

**Directory structure:**
```
.
├── pcap/              # Captured PCAP files
├── data/              # Extracted sessions and scores
├── logs/              # LLM analysis results
├── model.pkl          # Trained ML model
└── *.py               # Pipeline scripts
```

**Monitoring workflow:**
1. tcpdump captures traffic to rotating PCAP files (5-second windows)
2. Script detects new PCAP files (waits for write completion)
3. Extracts features → Scores with model → Analyzes with LLM
4. Repeats continuously (10-second polling interval)

## Installation

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install tcpdump tshark python3 python3-pip

# macOS
brew install tcpdump wireshark python3

# Python dependencies
pip3 install numpy scikit-learn

# Ollama (for LLM analysis)
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull qwen2:1.5b
```

### Setup

```bash
# Clone or download the pipeline
git clone <your-repo>
cd network-security-pipeline

# Make script executable
chmod +x run_pipeline.sh

# Test components
python3 feature_extraction.py --help
python3 model_train.py --help
python3 analyze_with_ollama.py --help
```

## Quick Start

### Option 1: Full automated monitoring
```bash
# Start capture and continuous analysis
sudo ./run_pipeline.sh monitor
```

### Option 2: Manual step-by-step
```bash
# 1. Capture traffic for 60 seconds
sudo tcpdump -i eth0 -w capture.pcap -G 60 -W 1

# 2. Extract features
python3 feature_extraction.py capture.pcap sessions.json

# 3. Train model (first time only)
python3 model_train.py sessions.json model.pkl

# 4. Score sessions
python3 model_score.py sessions.json scored.json model.pkl

# 5. Analyze anomalies
python3 analyze_with_ollama.py scored.json analysis.json 0.6 qwen2:1.5b
```

## Configuration

### Key parameters

**Anomaly detection:**
- `contamination` (model_train.py) - Expected anomaly rate (0.05-0.2)
- `threshold` (analyze_with_ollama.py) - Minimum score for analysis (0.5-0.8)

**LLM analysis:**
- `model` - Ollama model name (trade-off speed vs. accuracy)
- `timeout` - Analysis timeout in seconds (30-300)
- `max_workers` - Concurrent analysis threads (2-8)

**Packet capture:**
- `-G` flag - Rotation interval in seconds (5-60)
- `-W` flag - Number of rotating files (3-10)
- `-i` interface - Network interface to monitor

### Example configurations

**High-security environment (low false positives):**
```bash
python3 analyze_with_ollama.py scored.json analysis.json 0.8 deepseek-r1 180
```

**Fast processing (higher false positives):**
```bash
python3 analyze_with_ollama.py scored.json analysis.json 0.5 qwen2:1.5b 30
```

## Use Cases

### 1. Port Scan Detection
**Indicators:**
- High `unique_destination_count`
- Low `bytes_per_packet`
- Short connection durations

**Example alert:**
```json
{
  "status": "suspicious",
  "reason": "Source contacted 50+ destinations in 10 seconds",
  "action": "Monitor source 10.0.0.5 for continued scanning activity"
}
```

### 2. DDoS Detection
**Indicators:**
- Extremely high `packets_per_second`
- Many sources → single destination
- Uniform packet sizes

**Example alert:**
```json
{
  "status": "suspicious",
  "reason": "Abnormal traffic rate (5000 pps) indicates flood attack",
  "action": "iptables -A INPUT -d 192.168.1.10 -m limit --limit 100/s -j ACCEPT"
}
```

### 3. Data Exfiltration
**Indicators:**
- Large `total_bytes` outbound
- Long `duration` sessions
- Unusual destination IPs

**Example alert:**
```json
{
  "status": "suspicious",
  "reason": "Large data transfer (500MB) to external IP suggests exfiltration",
  "action": "Block outbound: iptables -A OUTPUT -d 93.184.216.34 -j DROP"
}
```

## Troubleshooting

### Timeout errors
**Problem:** LLM analysis times out frequently

**Solutions:**
```bash
# Increase timeout
python3 analyze_with_ollama.py scored.json analysis.json 0.6 qwen2:1.5b 180

# Use faster model
python3 analyze_with_ollama.py scored.json analysis.json 0.6 qwen2:1.5b 60

# Reduce concurrent workers (edit analyze_with_ollama.py)
max_workers = 2  # Default is 4
```

### No packets captured
**Problem:** PCAP files are empty

**Solutions:**
```bash
# Check interface name
ip link show  # Linux
ifconfig      # macOS

# Update run_pipeline.sh with correct interface
sudo tcpdump -i <correct-interface> -w test.pcap

# Check permissions
sudo usermod -aG wireshark $USER  # Linux
```

### Model accuracy issues
**Problem:** Too many false positives/negatives

**Solutions:**
```bash
# Retrain with different contamination rate
python3 model_train.py sessions.json model.pkl 0.05  # More sensitive
python3 model_train.py sessions.json model.pkl 0.20  # Less sensitive

# Collect more training data
# Run longer captures before training

# Adjust analysis threshold
python3 analyze_with_ollama.py scored.json analysis.json 0.7  # Fewer alerts
```

### JSON parsing errors from LLM
**Problem:** LLM doesn't return valid JSON

**Solution:** The script already handles this with fallback parsing. If persistent:
```bash
# Try different model
ollama pull llama3
python3 analyze_with_ollama.py scored.json analysis.json 0.6 llama3

# Check Ollama version
ollama --version  # Should be 0.1.0 or higher
```

## Performance

**Benchmarks (tested on 4-core CPU, 8GB RAM):**

| Component | Processing Rate | Notes |
|-----------|----------------|-------|
| feature_extraction | ~1000 packets/sec | Depends on PCAP size |
| model_train | ~10000 sessions/min | One-time cost |
| model_score | ~50000 sessions/sec | Very fast inference |
| analyze_with_ollama | ~0.5 sessions/sec | Bottleneck (LLM) |

**Optimization tips:**
- Use smaller LLM models (qwen2:1.5b vs deepseek-r1)
- Increase `threshold` to reduce LLM workload
- Adjust `max_workers` based on CPU cores
- Use GPU-accelerated Ollama for 5-10x speedup

## Security Considerations

- Run with minimal privileges (use `sudo` only for capture)
- Review LLM outputs before taking automated actions
- Store sensitive logs in encrypted volumes
- Rotate and archive old PCAP files regularly
- Monitor pipeline resource usage to prevent DoS

## License

MIT License - See LICENSE file for details

## Contributing

Contributions welcome! Please submit issues and pull requests.

## Acknowledgments

- Built with scikit-learn, tshark, tcpdump
- LLM integration via Ollama
- Inspired by network security best practices
