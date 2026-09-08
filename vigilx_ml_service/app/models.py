# vigilx_ml_service/app/models.py
from sklearn.ensemble import IsolationForest
import numpy as np
import pandas as pd
from .utils import transform_records_to_features, extract_ip_from_record, evaluate_threat_intelligence

class ThreatInferenceEngine:
    @staticmethod
    def analyze_batch(records: list) -> list:
        if not records:
            return []

        # 1. Compute Unsupervised AI Anomaly Scores
        features_df = transform_records_to_features(records)
        predictions = []
        raw_scores = []
        
        if not features_df.empty:
            model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
            predictions = model.fit_predict(features_df)
            raw_scores = model.score_samples(features_df)

        # 2. Correlate AI results with Threat Intelligence Feeds
        for idx, record in enumerate(records):
            # Extract basic ML info if computed
            is_ai_anomaly = bool(predictions[idx] == -1) if len(predictions) > idx else False
            scaled_score = (0.5 - raw_scores[idx]) * 100 if len(raw_scores) > idx else 0
            normalized_score = int(np.clip(scaled_score, 0, 100))
            
            # Step out and run the Threat Intelligence Lookup Pipeline
            ip_found = extract_ip_from_record(record)
            intel_report = evaluate_threat_intelligence(ip_found)
            
            # Record basic metrics
            record['source_ip'] = ip_found
            record['anomaly_score'] = normalized_score
            record['threat_intel_lookup'] = intel_report
            
            # 3. Hybrid Classification Rules Matrix
            if intel_report["matched"]:
                # If verified by Threat Intel, immediately flag it and force a high risk score
                record['is_anomaly'] = True
                record['anomaly_score'] = max(normalized_score, intel_report["confidence_score"])
                record['threat_verdict'] = f"CRITICAL_TI_MATCH: {intel_report['actor']}"
            elif is_ai_anomaly:
                # If only marked by ML, it's a structural anomaly
                record['is_anomaly'] = True
                record['threat_verdict'] = "SUSPICIOUS_STRUCTURAL_ANOMALY"
            else:
                # Completely clean records
                record['is_anomaly'] = False
                record['threat_verdict'] = "BENIGN_TRAFFIC"
            
        return records