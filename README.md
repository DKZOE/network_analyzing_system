# Network Security Monitoring Pipeline

This repository contains a complete network security monitoring system that captures network traffic, extracts session-level features, detects anomalies using machine learning, and optionally analyzes suspicious sessions with a Large Language Model (LLM) via **Ollama**.

---

## Features

- **Live packet capture** from network interfaces (supports macOS and Linux)
- **PCAP to session conversion** with numeric feature extraction
- **Anomaly detection** using Isolation Forest
- **LLM-based session analysis** (optional, using Ollama)
- Continuous monitoring with rotating capture files
- JSON outputs for both scored sessions and LLM analysis

---

## Directory Structure

.
├── pcap/                  # Captured PCAP files
├── data/                  # Extracted session features and scored JSON
├── logs/                  # LLM analysis results
├── feature_extraction.py  # Extracts session-level features from PCAP
├── model_train.py         # Trains IsolationForest model
├── model_score.py         # Scores sessions with trained model
├── analyze_with_ollama.py # Sends high-score sessions to Ollama for analysis
├── run_pipeline.sh        # Orchestrates the full pipeline
└── model.pkl              # Saved trained model and scaler

---

## Setup

1. Install dependencies:

```bash
# System packages
sudo apt-get install tcpdump tshark  # Linux
# macOS: tcpdump and tshark are typically preinstalled

# Python packages
pip install numpy scikit-learn

	2.	Install Ollama if LLM analysis is desired:
https://ollama.ai￼

⸻

Usage

Run full monitoring pipeline (default)

sudo ./run_pipeline.sh monitor

	•	Starts packet capture
	•	Continuously processes new PCAP files
	•	Scores sessions and optionally analyzes anomalies with LLM

Start/Stop capture only

sudo ./run_pipeline.sh start   # Only capture packets
sudo ./run_pipeline.sh stop    # Stop packet capture

Process a single PCAP file

sudo ./run_pipeline.sh process <pcap_file>

Train a new model

sudo ./run_pipeline.sh train <sessions.json>

	•	Uses IsolationForest for anomaly detection
	•	Saves model to model.pkl

⸻

Scripts Overview

1. feature_extraction.py
	•	Converts PCAP files to session-level JSON
	•	Extracted features per session:

src_ip, dst_ip
src_port, dst_port
duration
total_bytes
packet_count
packets_per_second
unique_destination_count
first_seen, last_seen

	•	Uses TShark for packet parsing
	•	Supports sliding-window unique destination count

⸻

2. model_train.py
	•	Trains an IsolationForest model using session features
	•	Feature normalization with StandardScaler
	•	Output: model.pkl (model + scaler)
	•	Optional contamination rate (default=0.1)

⸻

3. model_score.py
	•	Loads trained model (model.pkl) and scores sessions
	•	Adds anomaly scores and flags

{
  "anomaly_score": float,   // 0-1, higher = more anomalous
  "is_anomaly": 0 or 1      // predicted anomaly
}

	•	Summarizes high-score sessions and top anomalies

⸻

4. analyze_with_ollama.py
	•	Sends high-score sessions (anomaly_score ≥ threshold) to Ollama LLM
	•	Uses prompt-based analysis:
	•	Inputs: session 5-tuple, bytes, packets, rate, anomaly score
	•	Output: strict JSON

{
  "status": "normal" or "suspicious",
  "reason": "short, one sentence",
  "action": "firewall or IDS recommendation"
}

	•	Supports parallel analysis using ThreadPoolExecutor
	•	Retry logic and timeout handling included

⸻

5. run_pipeline.sh
	•	Master orchestration script
	•	Steps:
	1.	Start packet capture (rotating PCAP files)
	2.	Extract features
	3.	Train or load model
	4.	Score sessions
	5.	Analyze anomalies with Ollama (optional)
	•	Supports commands:
	•	start, stop, monitor, process, train

⸻

Example Workflow

# Start monitoring and capturing traffic
sudo ./run_pipeline.sh monitor

# Check scored sessions
cat data/out-20251101160000_scored.json

# Analyze LLM results
cat logs/out-20251101160000_analysis.json


⸻

Notes
	•	LLM analysis is optional. If ollama is not installed, it will skip this step.
	•	Maximum PCAP files per rotation can be configured in run_pipeline.sh.
	•	Anomaly threshold for LLM analysis is configurable (default 0.6).

---
