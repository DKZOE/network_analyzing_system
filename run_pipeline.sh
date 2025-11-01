#!/bin/bash
#
# run_pipeline.sh
# Orchestrates the complete network security monitoring pipeline
#

set -e  # Exit on error

# Configuration
PCAP_DIR="./pcap"
DATA_DIR="./data"
LOGS_DIR="./logs"
MODEL_FILE="model.pkl"
ANOMALY_THRESHOLD=0.6
OLLAMA_MODEL="qwen2:1.5b"

# Create directories
mkdir -p "$PCAP_DIR" "$DATA_DIR" "$LOGS_DIR"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" >&2
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

# Check dependencies
check_dependencies() {
    log "Checking dependencies..."
    
    local missing=0
    
    if ! command -v tcpdump &> /dev/null; then
        error "tcpdump not found. Please install: sudo apt-get install tcpdump"
        missing=1
    fi
    
    if ! command -v tshark &> /dev/null; then
        error "tshark not found. Please install: sudo apt-get install tshark"
        missing=1
    fi
    
    if ! command -v ollama &> /dev/null; then
        warn "ollama not found. Install from: https://ollama.ai"
        warn "LLM analysis will be skipped"
    fi
    
    if ! python3 -c "import sklearn" 2>/dev/null; then
        error "scikit-learn not found. Please install: pip install scikit-learn"
        missing=1
    fi
    
    if ! python3 -c "import numpy" 2>/dev/null; then
        error "numpy not found. Please install: pip install numpy"
        missing=1
    fi
    
    if [ $missing -eq 1 ]; then
        error "Missing dependencies. Please install them first."
        exit 1
    fi
    
    log "All dependencies satisfied"
}

# Start packet capture
start_capture() {
    log "Starting packet capture..."
    
    # Check if already running
    if pgrep -f "tcpdump.*$PCAP_DIR" > /dev/null; then
        warn "Capture already running"
        return
    fi
    
    # Start tcpdump in background with rotating buffer
        # Detect interface automatically (macOS vs Linux)
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS: detect active interface (default route)
        INTERFACE=$(route get default 2>/dev/null | awk '/interface: /{print $2}')
        
        # If detection fails fallback to en0
        [ -z "$INTERFACE" ] && INTERFACE="en0"
    else
        # Linux: use any
        INTERFACE="any"
    fi

    log "Using network interface: $INTERFACE"

    # Start tcpdump in background with rotating buffer
    sudo tcpdump -i "$INTERFACE" -w "$PCAP_DIR/out-%Y%m%d%H%M%S.pcap" -G 5 -W 3 &
    TCPDUMP_PID=$!
    
    echo $TCPDUMP_PID > "$PCAP_DIR/tcpdump.pid"
    log "Capture started (PID: $TCPDUMP_PID)"
    
    # Wait for first PCAP file
    sleep 5
}

# Stop packet capture
stop_capture() {
    if [ -f "$PCAP_DIR/tcpdump.pid" ]; then
        TCPDUMP_PID=$(cat "$PCAP_DIR/tcpdump.pid")
        log "Stopping capture (PID: $TCPDUMP_PID)..."
        sudo kill $TCPDUMP_PID 2>/dev/null || true
        rm -f "$PCAP_DIR/tcpdump.pid"
    fi
}

# Process a single PCAP file
process_pcap() {
    local pcap_file=$1
    local basename=$(basename "$pcap_file" .pcap)
    local sessions_file="$DATA_DIR/${basename}_sessions.json"
    local scored_file="$DATA_DIR/${basename}_scored.json"
    local analysis_file="$LOGS_DIR/${basename}_analysis.json"
    
    log "Processing $pcap_file..."
    
    # Step 1: Extract features
    log "  Extracting features..."
    python3 feature_extraction.py "$pcap_file" "$sessions_file"
    
    if [ ! -s "$sessions_file" ]; then
        warn "  No sessions extracted, skipping..."
        return
    fi
    
    # Step 2: Train or score
    if [ ! -f "$MODEL_FILE" ]; then
        log "  Training new model..."
        python3 model_train.py "$sessions_file" "$MODEL_FILE"
    fi
    
    log "  Scoring sessions..."
    python3 model_score.py "$sessions_file" "$scored_file" "$MODEL_FILE"
    
    # Step 3: Analyze with Ollama (if available)
    if command -v ollama &> /dev/null; then
        log "  Analyzing anomalies with LLM..."
        python3 analyze_with_ollama.py "$scored_file" "$analysis_file" "$ANOMALY_THRESHOLD" "$OLLAMA_MODEL"
    else
        warn "  Skipping LLM analysis (Ollama not available)"
    fi
    
    log "  Processing complete: $basename"
}

# Main monitoring loop
monitor_loop() {
    log "Starting monitoring loop (Ctrl+C to stop)..."
    
    local processed_files=()
    
    while true; do
        # Find new PCAP files
        for pcap_file in "$PCAP_DIR"/*.pcap; do
            [ -f "$pcap_file" ] || continue
            
            # Skip if already processed
            if [[ " ${processed_files[@]} " =~ " ${pcap_file} " ]]; then
                continue
            fi
            
            # Skip if file is being written (check size changes)
            # local size1=$(stat -c%s "$pcap_file" 2>/dev/null || echo 0)
            # sleep 2
            # local size2=$(stat -c%s "$pcap_file" 2>/dev/null || echo 0)
            # macOS file size check
            local size1=$(stat -f%z "$pcap_file" 2>/dev/null || echo 0)
            sleep 1
            local size2=$(stat -f%z "$pcap_file" 2>/dev/null || echo 0)
            
            if [ "$size1" != "$size2" ]; then
                continue  # File still growing
            fi
            
            # Process the PCAP
            process_pcap "$pcap_file"
            processed_files+=("$pcap_file")
        done
        
        sleep 10
    done
}

# Cleanup on exit
cleanup() {
    log "Shutting down..."
    stop_capture
    exit 0
}

trap cleanup INT TERM

# Main execution
main() {
    log "=== Network Security Monitoring Pipeline ==="
    
    check_dependencies
    
    # Parse command line arguments
    case "${1:-monitor}" in
        start)
            start_capture
            ;;
        stop)
            stop_capture
            ;;
        monitor)
            start_capture
            monitor_loop
            ;;
        process)
            if [ -z "$2" ]; then
                error "Usage: $0 process <pcap_file>"
                exit 1
            fi
            process_pcap "$2"
            ;;
        train)
            if [ -z "$2" ]; then
                error "Usage: $0 train <sessions.json>"
                exit 1
            fi
            python3 model_train.py "$2" "$MODEL_FILE"
            ;;
        *)
            echo "Usage: $0 {start|stop|monitor|process|train}"
            echo ""
            echo "Commands:"
            echo "  start   - Start packet capture only"
            echo "  stop    - Stop packet capture"
            echo "  monitor - Start capture and continuous monitoring (default)"
            echo "  process - Process a single PCAP file"
            echo "  train   - Train model from sessions JSON"
            exit 1
            ;;
    esac
}

main "$@"