#!/usr/bin/env python3
"""
analyze_with_ollama.py
Send high-score anomalous sessions to Ollama for analysis.
"""

import json
import sys
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import time

def load_scored_sessions(json_file):
    """Load scored sessions from JSON."""
    with open(json_file, 'r') as f:
        return json.load(f)

def build_analysis_prompt(session):
    """Build prompt for LLM analysis."""
    baseline_mean = session.get("baseline_mean", "unknown")
    baseline_deviation = session.get("deviation_factor", "unknown")

    prompt = f"""
Analyze this network session and classify it.

Return ONLY valid JSON. No explanations, no commentary.

Session:
src={session['src_ip']}:{session['src_port']}
dst={session['dst_ip']}:{session['dst_port']}
bytes={session['total_bytes']}
packets={session['packet_count']}
rate={session['packets_per_second']}
score={session['anomaly_score']}

Output Format (strict JSON):
{{
  "status": "normal" or "suspicious",
  "reason": "short, one sentence",
  "action": "firewall or IDS recommendation"
}}
""".replace("{", "{{").replace("}", "}}", 1).replace("}}", "}", 1)

    return prompt

def analyze_with_ollama(session, model="qwen2:1.5b", timeout=120, max_retries=2):
    """Send session to Ollama for analysis with retry logic."""
    prompt = build_analysis_prompt(session)
    
    for attempt in range(max_retries):
        try:
            # Ollama 프로세스 실행
            result = subprocess.run(
                ["ollama", "run", model],
                input=prompt,
                text=True,
                capture_output=True,
                timeout=timeout
            )
            
            if result.returncode == 0:
                response = result.stdout.strip()
                
                # JSON 파싱 시도
                try:
                    # JSON만 추출 (```json ``` 태그 제거)
                    if "```json" in response:
                        json_start = response.find("```json") + 7
                        json_end = response.find("```", json_start)
                        response = response[json_start:json_end].strip()
                    elif "```" in response:
                        json_start = response.find("```") + 3
                        json_end = response.find("```", json_start)
                        response = response[json_start:json_end].strip()
                    
                    # JSON 유효성 검사
                    parsed = json.loads(response)
                    return response
                except json.JSONDecodeError:
                    # JSON 파싱 실패시 원본 반환
                    return response
            else:
                error_msg = f"Error (attempt {attempt + 1}/{max_retries}): {result.stderr}"
                if attempt < max_retries - 1:
                    print(f"    {error_msg} - Retrying...")
                    time.sleep(2)
                else:
                    return error_msg
        
        except subprocess.TimeoutExpired:
            error_msg = f"Error: Analysis timeout after {timeout}s (attempt {attempt + 1}/{max_retries})"
            if attempt < max_retries - 1:
                print(f"    {error_msg} - Retrying with longer timeout...")
                timeout += 60  # 타임아웃 증가
                time.sleep(2)
            else:
                return error_msg
        
        except FileNotFoundError:
            return "Error: Ollama not found. Please install Ollama (https://ollama.ai)"
        
        except Exception as e:
            return f"Error: {str(e)}"
    
    return "Error: Max retries exceeded"

def main(scored_file, output_file, threshold=0.6, model="qwen2:1.5b", timeout=30):
    """Main analysis pipeline."""
    print(f"Loading scored sessions from {scored_file}...")
    sessions = load_scored_sessions(scored_file)
    
    # Filter high-score sessions
    high_score_sessions = [s for s in sessions if s['anomaly_score'] >= threshold]
    
    print(f"Found {len(high_score_sessions)} sessions with score ≥ {threshold}")
    print(f"Using model: {model} (timeout: {timeout}s)\n")
    
    if not high_score_sessions:
        print("No sessions to analyze.")
        return
    
    # Analyze each session
    results = []
    
    def worker(session):
        """각 세션을 LLM으로 분석"""
        start_time = datetime.now()
        analysis = analyze_with_ollama(session, model, timeout)
        elapsed = (datetime.now() - start_time).total_seconds()
        return {
            "timestamp": datetime.now().isoformat(),
            "session": session,
            "llm_analysis": analysis,
            "analysis_time_seconds": round(elapsed, 2)
        }

    # 최대 4개 세션을 동시에 분석
    max_workers = 4
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(worker, s): s for s in high_score_sessions}
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            session = result["session"]
            print(f"Completed session {session['src_ip']}->{session['dst_ip']}")


    
    # Save final results
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    # Remove temp file if exists
    temp_file = Path(output_file + ".tmp")
    if temp_file.exists():
        temp_file.unlink()
    
    print(f"\n{'='*60}")
    print(f"Analysis complete!")
    print(f"Results saved to: {output_file}")
    print(f"Total sessions analyzed: {len(results)}")
    print(f"{'='*60}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python analyze_with_ollama.py <scored.json> <output.json> [threshold] [model] [timeout]")
        print("  threshold: minimum anomaly score (default: 0.6)")
        print("  model: ollama model name (default: qwen2:1.5b)")
        print("  timeout: analysis timeout in seconds (default: 120)")
        print("\nExample:")
        print("  python analyze_with_ollama.py scored_sessions.json analysis_results.json 0.7 llama3 180")
        sys.exit(1)
    
    scored_file = sys.argv[1]
    output_file = sys.argv[2]
    threshold = float(sys.argv[3]) if len(sys.argv) > 3 else 0.6
    model = sys.argv[4] if len(sys.argv) > 4 else "qwen2:1.5b"
    timeout = int(sys.argv[5]) if len(sys.argv) > 5 else 120
    
    main(scored_file, output_file, threshold, model, timeout)