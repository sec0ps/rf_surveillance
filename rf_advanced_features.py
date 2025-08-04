#!/usr/bin/env python3
# =============================================================================
# RF Scanner Detection System - Passive RF Surveillance Detection
# =============================================================================
#
# Author: Keith Pachulski
# Company: Red Cell Security, LLC
# Email: keith@redcellsecurity.org
# Website: www.redcellsecurity.org
#
# Copyright (c) 2025 Keith Pachulski. All rights reserved.
#
# License: This software is licensed under the MIT License.
#          You are free to use, modify, and distribute this software
#          in accordance with the terms of the license.
#
# Purpose: This module is part of the RF Scanner Detection System, designed to
#          passively identify unauthorized radio frequency scanning and monitoring
#          activities using HackRF One SDR hardware. It provides real-time detection
#          of sequential scanning, random scanning, targeted monitoring, and active
#          RF probes across VHF, UHF, and ISM frequency bands for defensive
#          cybersecurity operations and communications security (COMSEC) protection.
#
# DISCLAIMER: This software is provided "as-is," without warranty of any kind,
#             express or implied, including but not limited to the warranties
#             of merchantability, fitness for a particular purpose, and non-infringement.
#             In no event shall the authors or copyright holders be liable for any claim,
#             damages, or other liability, whether in an action of contract, tort, or otherwise,
#             arising from, out of, or in connection with the software or the use or other dealings
#             in the software.
#
# LEGAL NOTICE: This system is designed for authorized security operations and
#               legitimate RF monitoring only. Users must ensure compliance with
#               local laws and regulations regarding radio frequency monitoring
#               and electronic surveillance before deployment.
#
# =============================================================================

import json
import logging
from datetime import datetime
from collections import defaultdict
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from scipy import signal, stats
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
import folium
from geopy.distance import geodesic
import requests
import hashlib
from typing import Dict, List, Tuple, Optional
import warnings
warnings.filterwarnings('ignore

logger = logging.getLogger(__name__)

class AdvancedSignalAnalyzer:
    """Enhanced signal analysis with ML and statistical methods"""
    
    def __init__(self):
        self.signature_database = {}
        self.scanner_fingerprints = {}
        
    # KEEP - This is unique functionality not in rf_scanner_detection.py
    def cluster_scanner_signatures(self, signatures: List[Dict]) -> Dict:
        """Cluster similar scanner signatures to identify device types"""
        
        if len(signatures) < 3:
            return {'clusters': [], 'device_types': []}
        
        # Convert signatures to feature matrix
        features = []
        for sig in signatures:
            feature_vector = [
                sig['spectral_centroid'],
                sig['spectral_bandwidth'], 
                sig['phase_noise'],
                sig['rise_time'],
                sig['freq_deviation'],
                sig['signal_entropy']
            ]
            features.append(feature_vector)
        
        features = np.array(features)
        
        # Normalize features
        scaler = StandardScaler()
        features_scaled = scaler.fit_transform(features)
        
        # DBSCAN clustering
        clustering = DBSCAN(eps=0.5, min_samples=2)
        cluster_labels = clustering.fit_predict(features_scaled)
        
        # Analyze clusters
        unique_clusters = set(cluster_labels)
        cluster_analysis = {}
        
        for cluster_id in unique_clusters:
            if cluster_id == -1:  # Noise points
                continue
                
            cluster_indices = np.where(cluster_labels == cluster_id)[0]
            cluster_features = features[cluster_indices]
            
            cluster_analysis[cluster_id] = {
                'count': len(cluster_indices),
                'centroid': np.mean(cluster_features, axis=0),
                'std': np.std(cluster_features, axis=0),
                'device_type': self._classify_device_from_cluster(np.mean(cluster_features, axis=0))
            }
        
        return {
            'clusters': cluster_analysis,
            'cluster_labels': cluster_labels,
            'n_clusters': len(unique_clusters) - (1 if -1 in unique_clusters else 0)
        }
    
    # KEEP - Rename to avoid conflict with rf_scanner_detection.py
    def _classify_device_from_cluster(self, feature_centroid: np.ndarray) -> str:
        """Classify scanner device type based on signature"""
        
        spectral_centroid, spectral_bandwidth, phase_noise, rise_time, freq_dev, entropy = feature_centroid
        
        # Classification rules based on typical scanner characteristics
        if phase_noise > 0.1 and rise_time < 0.01:
            return "Professional Scanner (Fast Switching)"
        elif spectral_bandwidth > 1000 and freq_dev > 500:
            return "Wideband Scanner (SDR-based)"
        elif rise_time > 0.05 and phase_noise < 0.05:
            return "Consumer Scanner (Slow Switching)"
        elif entropy > 6.0:
            return "Digital Trunking Scanner"
        else:
            return "Unknown Scanner Type"

class ThreatIntelligenceIntegrator:
    """Integration with threat intelligence feeds and databases"""
    
    def __init__(self):
        self.known_scanner_signatures = {}
        self.threat_feeds = []
        self.ioc_database = {}
        
    # KEEP - Unique functionality
    def load_scanner_database(self, database_file: str):
        """Load known scanner signatures from database"""
        try:
            import json
            with open(database_file, 'r') as f:
                self.known_scanner_signatures = json.load(f)
        except FileNotFoundError:
            # Create empty database
            self.known_scanner_signatures = {
                'uniden_bc125at': {
                    'frequency_step': 25000,
                    'scan_rate': 100,  # channels per second
                    'phase_noise_signature': 0.05,
                    'rise_time': 0.02
                },
                'rtlsdr_generic': {
                    'frequency_step': 1000000,
                    'scan_rate': 50,
                    'phase_noise_signature': 0.15,
                    'rise_time': 0.001
                }
            }
            self._save_scanner_database(database_file)
    
    # KEEP - Unique functionality
    def _save_scanner_database(self, database_file: str):
        """Save scanner signatures to database"""
        import json
        with open(database_file, 'w') as f:
            json.dump(self.known_scanner_signatures, f, indent=2)
    
    # KEEP - Unique functionality
    def match_signature(self, observed_signature: Dict) -> List[Dict]:
        """Match observed signature against known scanner database"""
        matches = []
        
        for scanner_id, known_sig in self.known_scanner_signatures.items():
            similarity_score = self._calculate_similarity_score(
                observed_signature, known_sig
            )
            
            if similarity_score > 0.7:  # 70% similarity threshold
                matches.append({
                    'scanner_id': scanner_id,
                    'similarity': similarity_score,
                    'confidence': min(similarity_score * 1.2, 1.0)
                })
        
        return sorted(matches, key=lambda x: x['similarity'], reverse=True)
    
    # KEEP - Renamed to avoid conflict
    def _calculate_similarity_score(self, sig1: Dict, sig2: Dict) -> float:
        """Calculate similarity between two signatures"""
        common_keys = set(sig1.keys()) & set(sig2.keys())
        if not common_keys:
            return 0.0
        
        similarities = []
        for key in common_keys:
            if isinstance(sig1[key], (int, float)) and isinstance(sig2[key], (int, float)):
                # Normalize the difference
                max_val = max(abs(sig1[key]), abs(sig2[key]), 1e-6)
                diff = abs(sig1[key] - sig2[key]) / max_val
                similarity = max(0, 1 - diff)
                similarities.append(similarity)
        
        return np.mean(similarities) if similarities else 0.0
    
    # KEEP - Unique functionality
    def generate_ioc(self, detection_data: Dict) -> Dict:
        """Generate Indicator of Compromise from detection"""
        
        # Create unique IOC hash based on signature
        signature_str = str(sorted(detection_data.items()))
        ioc_hash = hashlib.sha256(signature_str.encode()).hexdigest()[:16]
        
        ioc = {
            'id': f"RF_SCAN_{ioc_hash}",
            'type': 'rf_scanner_detection',
            'first_seen': detection_data.get('timestamp'),
            'last_seen': detection_data.get('timestamp'),
            'frequency': detection_data.get('frequency'),
            'confidence': detection_data.get('confidence'),
            'signature_hash': ioc_hash,
            'threat_level': self._classify_threat_level(detection_data),
            'attributes': {
                'detection_type': detection_data.get('detection_type'),
                'signal_strength': detection_data.get('signal_strength'),
                'duration': detection_data.get('duration')
            }
        }
        
        self.ioc_database[ioc['id']] = ioc
        return ioc
    
    # KEEP - Renamed to avoid conflict with rf_scanner_detection.py
    def _classify_threat_level(self, detection_data: Dict) -> str:
        """Classify threat level based on detection characteristics"""
        confidence = detection_data.get('confidence', 0)
        detection_type = detection_data.get('detection_type', '')
        duration = detection_data.get('duration', 0)
        
        if confidence > 0.9 and detection_type == 'targeted' and duration > 300:
            return 'HIGH'
        elif confidence > 0.7 and detection_type in ['scanning', 'targeted']:
            return 'MEDIUM'
        else:
            return 'LOW'

class SIEMIntegrator:
    """Integration with SIEM systems for centralized security monitoring"""
    
    def __init__(self, siem_config):
        self.siem_endpoint = siem_config['endpoint']
        self.api_key = siem_config['api_key']
        self.source_identifier = "RF_Scanner_Detection_System"
        
    def send_detection_event(self, detection, enhanced_analysis=None):
        """Send detection event to SIEM"""
        
        # Create SIEM event structure
        event = {
            "timestamp": detection.timestamp.isoformat(),
            "source": self.source_identifier,
            "event_type": "RF_RECONNAISSANCE_DETECTED",
            "severity": self._calculate_severity(detection),
            "fields": {
                "frequency_mhz": detection.frequency / 1e6,
                "signal_strength_dbm": detection.signal_strength,
                "detection_type": detection.detection_type,
                "confidence_score": detection.confidence,
                "duration_seconds": detection.duration,
                "metadata": detection.metadata
            }
        }
        
        # Add enhanced analysis if available
        if enhanced_analysis:
            event["fields"]["scanner_signature"] = enhanced_analysis.get('signature', {})
            event["fields"]["scanner_matches"] = enhanced_analysis.get('scanner_matches', [])
            event["fields"]["threat_ioc"] = enhanced_analysis.get('ioc', {})
        
        # Send to SIEM
        try:
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                self.siem_endpoint,
                headers=headers,
                data=json.dumps(event),
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info(f"SIEM event sent successfully: {event['event_type']}")
            else:
                logger.error(f"SIEM event failed: {response.status_code} - {response.text}")
                
        except Exception as e:
            logger.error(f"SIEM integration error: {e}")
    
    def _calculate_severity(self, detection):
        """Calculate SIEM severity level"""
        if detection.confidence > 0.9:
            return "CRITICAL"
        elif detection.confidence > 0.7:
            return "HIGH"
        elif detection.confidence > 0.5:
            return "MEDIUM"
        else:
            return "LOW"
