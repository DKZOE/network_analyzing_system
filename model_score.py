#!/usr/bin/env python3
"""
model_score.py
Score sessions using trained IsolationForest model.
"""

import json
import sys
import pickle
import numpy as np
from pathlib import Path

def load_model(model_file="model.pkl"):
    """Load trained model and scaler."""
    if not Path(model_file).exists():
        print(f"Error: Model file {model_file} not found", file=sys.stderr)
        print("Please train a model first using model_train.py", file=sys.stderr)
        sys.exit(1)
    
    with open(model_file, 'rb') as f:
        data = pickle.load(f)
    
    return data['model'], data['scaler']

def load_sessions(json_file):
    """Load session features from JSON."""
    with open(json_file, 'r') as f:
        return json.load(f)

def prepare_features(sessions):
    """Convert sessions to numeric feature matrix."""
    features = []
    
    for session in sessions:
        feature_vector = [
            session.get("duration", 0),
            session.get("total_bytes", 0),
            session.get("packet_count", 0),
            session.get("packets_per_second", 0),
            session.get("unique_destination_count", 0)
        ]
        features.append(feature_vector)
    
    return np.array(features)

def score_sessions(sessions, model, scaler):
    """Score sessions and add anomaly scores."""
    features = prepare_features(sessions)
    features_scaled = scaler.transform(features)
    
    # Get anomaly scores (negative scores are more anomalous)
    scores = model.score_samples(features_scaled)
    
    # Normalize scores to 0-1 range (higher = more anomalous)
    # IsolationForest returns negative scores, we invert and normalize
    min_score = scores.min()
    max_score = scores.max()
    
    if max_score != min_score:
        normalized_scores = 1 - (scores - min_score) / (max_score - min_score)
    else:
        normalized_scores = np.zeros_like(scores)
    
    # Add scores to sessions
    for i, session in enumerate(sessions):
        session['anomaly_score'] = float(normalized_scores[i])
        session['is_anomaly'] = int(model.predict(features_scaled[i].reshape(1, -1))[0] == -1)
    
    return sessions

def main(json_file, output_file, model_file="model.pkl"):
    """Main scoring pipeline."""
    print(f"Loading model from {model_file}...")
    model, scaler = load_model(model_file)
    
    print(f"Loading sessions from {json_file}...")
    sessions = load_sessions(json_file)
    print(f"Loaded {len(sessions)} sessions")
    
    # Score sessions
    print("Scoring sessions...")
    scored_sessions = score_sessions(sessions, model, scaler)
    
    # Save results
    with open(output_file, 'w') as f:
        json.dump(scored_sessions, f, indent=2)
    
    # Summary
    anomalies = [s for s in scored_sessions if s['is_anomaly']]
    high_score = [s for s in scored_sessions if s['anomaly_score'] >= 0.6]
    
    print(f"\nScoring Summary:")
    print(f"  Total sessions: {len(scored_sessions)}")
    print(f"  Detected anomalies: {len(anomalies)}")
    print(f"  High score (≥0.6): {len(high_score)}")
    print(f"  Saved to: {output_file}")
    
    # Show top 5 anomalies
    if high_score:
        print("\nTop anomalous sessions:")
        sorted_sessions = sorted(scored_sessions, key=lambda x: x['anomaly_score'], reverse=True)
        for i, session in enumerate(sorted_sessions[:5], 1):
            print(f"  {i}. {session['src_ip']}:{session['src_port']} -> "
                  f"{session['dst_ip']}:{session['dst_port']} "
                  f"(score: {session['anomaly_score']:.3f})")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python model_score.py <sessions.json> <output.json> [model.pkl]")
        sys.exit(1)
    
    json_file = sys.argv[1]
    output_file = sys.argv[2]
    model_file = sys.argv[3] if len(sys.argv) > 3 else "model.pkl"
    
    main(json_file, output_file, model_file)