#!/usr/bin/env python3
"""
model_train.py
Train IsolationForest model on extracted session features.
"""

import json
import sys
import pickle
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from pathlib import Path

def load_sessions(json_file):
    """Load session features from JSON."""
    with open(json_file, 'r') as f:
        return json.load(f)

def prepare_features(sessions):
    """Convert sessions to numeric feature matrix."""
    features = []
    
    for session in sessions:
        # Extract numeric features only
        feature_vector = [
            session.get("duration", 0),
            session.get("total_bytes", 0),
            session.get("packet_count", 0),
            session.get("packets_per_second", 0),
            session.get("unique_destination_count", 0)
        ]
        features.append(feature_vector)
    
    return np.array(features)

def train_model(features, contamination=0.1):
    """Train IsolationForest model."""
    print(f"Training on {len(features)} samples...")
    
    # Normalize features
    scaler = StandardScaler()
    features_scaled = scaler.fit_transform(features)
    
    # Train Isolation Forest
    model = IsolationForest(
        contamination=contamination,
        random_state=42,
        n_estimators=100,
        max_samples='auto',
        n_jobs=-1
    )
    
    model.fit(features_scaled)
    
    print("Model trained successfully")
    
    return model, scaler

def save_model(model, scaler, model_file="model.pkl"):
    """Save trained model and scaler."""
    with open(model_file, 'wb') as f:
        pickle.dump({'model': model, 'scaler': scaler}, f)
    
    print(f"Model saved to {model_file}")

def main(json_file, model_file="model.pkl", contamination=0.1):
    """Main training pipeline."""
    print(f"Loading sessions from {json_file}...")
    sessions = load_sessions(json_file)
    
    if len(sessions) < 10:
        print("Error: Need at least 10 sessions for training", file=sys.stderr)
        sys.exit(1)
    
    print(f"Loaded {len(sessions)} sessions")
    
    # Prepare feature matrix
    features = prepare_features(sessions)
    print(f"Feature matrix shape: {features.shape}")
    
    # Train model
    model, scaler = train_model(features, contamination)
    
    # Save model
    save_model(model, scaler, model_file)
    
    # Show training summary
    predictions = model.predict(scaler.transform(features))
    n_anomalies = np.sum(predictions == -1)
    print(f"\nTraining Summary:")
    print(f"  Total samples: {len(predictions)}")
    print(f"  Anomalies detected: {n_anomalies}")
    print(f"  Anomaly rate: {n_anomalies/len(predictions)*100:.2f}%")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python model_train.py <sessions.json> [model.pkl] [contamination]")
        sys.exit(1)
    
    json_file = sys.argv[1]
    model_file = sys.argv[2] if len(sys.argv) > 2 else "model.pkl"
    contamination = float(sys.argv[3]) if len(sys.argv) > 3 else 0.1
    
    main(json_file, model_file, contamination)