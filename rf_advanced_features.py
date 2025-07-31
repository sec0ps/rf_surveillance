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
        
    def analyze_modulation_signature(self, iq_data: np.ndarray, sample_rate: float) -> Dict:
        """Analyze modulation characteristics to fingerprint scanner devices"""
        
        # Extract signal features
        instantaneous_phase = np.unwrap(np.angle(iq_data))
        instantaneous_freq = np.diff(instantaneous_phase) * sample_rate / (2 * np.pi)
        
        # Calculate spectral features
        freqs, psd = signal.welch(iq_data, sample_rate, nperseg=1024)
        spectral_centroid = np.sum(freqs * psd) / np.sum(psd)
        spectral_bandwidth = np.sqrt(np.sum(((freqs - spectral_centroid) ** 2) * psd) / np.sum(psd))
        
        # Timing analysis
        envelope = np.abs(signal.hilbert(np.real(iq_data)))
        rise_time = self._calculate_rise_time(envelope)
        
        # Phase noise analysis
        phase_noise = np.var(np.diff(instantaneous_phase))
        
        signature = {
            'spectral_centroid': spectral_centroid,
            'spectral_bandwidth': spectral_bandwidth,
            'phase_noise': phase_noise,
            'rise_time': rise_time,
            'freq_deviation': np.std(instantaneous_freq),
            'signal_entropy': self._calculate_entropy(envelope)
        }
        
        return signature
    
    def _calculate_rise_time(self, envelope: np.ndarray) -> float:
        """Calculate signal rise time (10% to 90% of peak)"""
        peak_value = np.max(envelope)
        rise_start = np.where(envelope > 0.1 * peak_value)[0]
        rise_end = np.where(envelope > 0.9 * peak_value)[0]
        
        if len(rise_start) > 0 and len(rise_end) > 0:
            return (rise_end[0] - rise_start[0]) / len(envelope)
        return 0.0
    
    def _calculate_entropy(self, signal_data: np.ndarray) -> float:
        """Calculate signal entropy for randomness analysis"""
        hist, _ = np.histogram(signal_data, bins=50, density=True)
        hist = hist[hist > 0]  # Remove zero bins
        return -np.sum(hist * np.log2(hist))
    
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
                'device_type': self._classify_device_type(np.mean(cluster_features, axis=0))
            }
        
        return {
            'clusters': cluster_analysis,
            'cluster_labels': cluster_labels,
            'n_clusters': len(unique_clusters) - (1 if -1 in unique_clusters else 0)
        }
    
    def _classify_device_type(self, feature_centroid: np.ndarray) -> str:
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
    
    def _save_scanner_database(self, database_file: str):
        """Save scanner signatures to database"""
        import json
        with open(database_file, 'w') as f:
            json.dump(self.known_scanner_signatures, f, indent=2)
    
    def match_signature(self, observed_signature: Dict) -> List[Dict]:
        """Match observed signature against known scanner database"""
        matches = []
        
        for scanner_id, known_sig in self.known_scanner_signatures.items():
            similarity_score = self._calculate_signature_similarity(
                observed_signature, known_sig
            )
            
            if similarity_score > 0.7:  # 70% similarity threshold
                matches.append({
                    'scanner_id': scanner_id,
                    'similarity': similarity_score,
                    'confidence': min(similarity_score * 1.2, 1.0)
                })
        
        return sorted(matches, key=lambda x: x['similarity'], reverse=True)
    
    def _calculate_signature_similarity(self, sig1: Dict, sig2: Dict) -> float:
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
            'threat_level': self._assess_threat_level(detection_data),
            'attributes': {
                'detection_type': detection_data.get('detection_type'),
                'signal_strength': detection_data.get('signal_strength'),
                'duration': detection_data.get('duration')
            }
        }
        
        self.ioc_database[ioc['id']] = ioc
        return ioc
    
    def _assess_threat_level(self, detection_data: Dict) -> str:
        """Assess threat level based on detection characteristics"""
        confidence = detection_data.get('confidence', 0)
        detection_type = detection_data.get('detection_type', '')
        duration = detection_data.get('duration', 0)
        
        if confidence > 0.9 and detection_type == 'targeted' and duration > 300:
            return 'HIGH'
        elif confidence > 0.7 and detection_type in ['scanning', 'targeted']:
            return 'MEDIUM'
        else:
            return 'LOW'

class ReportingAndVisualization:
    """Advanced reporting and visualization capabilities"""
    
    def __init__(self):
        self.detection_history = []
        
    def generate_threat_report(self, detections: List, output_file: str = 'threat_report.html'):
        """Generate comprehensive threat assessment report"""
        
        # Convert to DataFrame for analysis
        df = pd.DataFrame([{
            'timestamp': d.timestamp,
            'frequency_mhz': d.frequency / 1e6,
            'signal_strength': d.signal_strength,
            'detection_type': d.detection_type,
            'confidence': d.confidence,
            'duration': d.duration
        } for d in detections])
        
        if df.empty:
            return "No detections to report"
        
        # Create visualizations
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        
        # Detection timeline
        df['hour'] = df['timestamp'].dt.hour
        hourly_counts = df.groupby('hour').size()
        axes[0, 0].bar(hourly_counts.index, hourly_counts.values)
        axes[0, 0].set_title('Detections by Hour of Day')
        axes[0, 0].set_xlabel('Hour')
        axes[0, 0].set_ylabel('Count')
        
        # Frequency distribution
        axes[0, 1].hist(df['frequency_mhz'], bins=20, alpha=0.7)
        axes[0, 1].set_title('Frequency Distribution of Detections')
        axes[0, 1].set_xlabel('Frequency (MHz)')
        axes[0, 1].set_ylabel('Count')
        
        # Detection type distribution
        type_counts = df['detection_type'].value_counts()
        axes[1, 0].pie(type_counts.values, labels=type_counts.index, autopct='%1.1f%%')
        axes[1, 0].set_title('Detection Types')
        
        # Confidence vs Signal Strength
        scatter = axes[1, 1].scatter(df['signal_strength'], df['confidence'], 
                                   c=df['duration'], cmap='viridis', alpha=0.6)
        axes[1, 1].set_xlabel('Signal Strength (dBm)')
        axes[1, 1].set_ylabel('Confidence')
        axes[1, 1].set_title('Confidence vs Signal Strength')
        plt.colorbar(scatter, ax=axes[1, 1], label='Duration (s)')
        
        plt.tight_layout()
        plt.savefig('detection_analysis.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        # Generate HTML report
        html_report = self._create_html_report(df, detections)
        
        with open(output_file, 'w') as f:
            f.write(html_report)
        
        return f"Report generated: {output_file}"
    
    def _create_html_report(self, df: pd.DataFrame, detections: List) -> str:
        """Create HTML threat assessment report"""
        
        # Calculate statistics
        total_detections = len(df)
        high_confidence = len(df[df['confidence'] > 0.8])
        unique_frequencies = df['frequency_mhz'].nunique()
        avg_signal_strength = df['signal_strength'].mean()
        
        # Threat level assessment
        if high_confidence > 10:
            threat_level = "HIGH"
            threat_color = "red"
        elif high_confidence > 3:
            threat_level = "MEDIUM" 
            threat_color = "orange"
        else:
            threat_level = "LOW"
            threat_color = "green"
        
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>RF Scanner Detection Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .threat-level {{ color: {threat_color}; font-weight: bold; font-size: 24px; }}
                .stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
                .stat-box {{ background-color: #f9f9f9; padding: 15px; border-radius: 5px; text-align: center; }}
                .detection-table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                .detection-table th, .detection-table td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                .detection-table th {{ background-color: #f2f2f2; }}
                .high-confidence {{ background-color: #ffebee; }}
                .medium-confidence {{ background-color: #fff3e0; }}
                .low-confidence {{ background-color: #f1f8e9; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>RF Scanner Detection Report</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p class="threat-level">Threat Level: {threat_level}</p>
            </div>
            
            <div class="stats">
                <div class="stat-box">
                    <h3>{total_detections}</h3>
                    <p>Total Detections</p>
                </div>
                <div class="stat-box">
                    <h3>{high_confidence}</h3>
                    <p>High Confidence</p>
                </div>
                <div class="stat-box">
                    <h3>{unique_frequencies}</h3>
                    <p>Unique Frequencies</p>
                </div>
                <div class="stat-box">
                    <h3>{avg_signal_strength:.1f} dBm</h3>
                    <p>Avg Signal Strength</p>
                </div>
            </div>
            
            <img src="detection_analysis.png" alt="Detection Analysis" style="width: 100%; max-width: 800px;">
            
            <h2>Recent High-Confidence Detections</h2>
            <table class="detection-table">
                <tr>
                    <th>Timestamp</th>
                    <th>Frequency (MHz)</th>
                    <th>Type</th>
                    <th>Confidence</th>
                    <th>Signal Strength (dBm)</th>
                    <th>Duration (s)</th>
                </tr>
        """
        
        # Add high-confidence detections to table
        high_conf_detections = df[df['confidence'] > 0.7].sort_values('confidence', ascending=False).head(20)
        
        for _, row in high_conf_detections.iterrows():
            confidence_class = 'high-confidence' if row['confidence'] > 0.8 else 'medium-confidence'
            html_template += f"""
                <tr class="{confidence_class}">
                    <td>{row['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}</td>
                    <td>{row['frequency_mhz']:.3f}</td>
                    <td>{row['detection_type']}</td>
                    <td>{row['confidence']:.2f}</td>
                    <td>{row['signal_strength']:.1f}</td>
                    <td>{row['duration']:.1f}</td>
                </tr>
            """
        
        html_template += """
            </table>
            
            <h2>Recommendations</h2>
            <ul>
        """
        
        # Add specific recommendations based on detections
        if threat_level == "HIGH":
            html_template += """
                <li><strong>Immediate Action Required:</strong> Multiple high-confidence scanner detections indicate active surveillance</li>
                <li>Consider changing radio frequencies/protocols if operationally feasible</li>
                <li>Implement additional COMSEC measures</li>
                <li>Investigate source of scanning activity</li>
            """
        elif threat_level == "MEDIUM":
            html_template += """
                <li>Monitor situation closely for escalation</li>
                <li>Review communication security procedures</li>
                <li>Consider additional countermeasures if pattern continues</li>
            """
        else:
            html_template += """
                <li>Continue monitoring - current detections may be routine scanner usage</li>
                <li>Maintain situational awareness</li>
            """
        
        html_template += """
            </ul>
        </body>
        </html>
        """
        
        return html_template

class EnhancedRFDetector:
    """Enhanced RF detector with all advanced features"""
    
    def __init__(self):
        self.signal_analyzer = AdvancedSignalAnalyzer()
        self.threat_intel = ThreatIntelligenceIntegrator()
        self.reporting = ReportingAndVisualization()

    def process_enhanced_detection(self, detection_data: Dict, iq_data: np.ndarray = None):
        """Process detection with all advanced analysis"""
        
        results = {
            'basic_detection': detection_data,
            'enhanced_analysis': {}
        }
        
        # Signal signature analysis
        if iq_data is not None:
            signature = self.signal_analyzer.analyze_modulation_signature(
                iq_data, detection_data.get('sample_rate', 2e6)
            )
            results['enhanced_analysis']['signature'] = signature
            
            # Match against known scanners
            matches = self.threat_intel.match_signature(signature)
            results['enhanced_analysis']['scanner_matches'] = matches
        
        # Generate IOC
        ioc = self.threat_intel.generate_ioc(detection_data)
        results['enhanced_analysis']['ioc'] = ioc
        
        return results
        
class AutomatedResponseSystem:
    def __init__(self):
        self.response_rules = []
        self.active_responses = {}
        
    def add_response_rule(self, rule):
        """Add automated response rule"""
        self.response_rules.append(rule)
    
    def evaluate_detection(self, detection, enhanced_analysis=None):
        """Evaluate detection against response rules"""
        
        for rule in self.response_rules:
            if self._rule_matches(rule, detection, enhanced_analysis):
                self._execute_response(rule, detection)
    
    def _rule_matches(self, rule, detection, enhanced_analysis):
        """Check if detection matches response rule criteria"""
        
        conditions = rule.get('conditions', {})
        
        # Check confidence threshold
        if 'min_confidence' in conditions:
            if detection.confidence < conditions['min_confidence']:
                return False
        
        # Check detection type
        if 'detection_types' in conditions:
            if detection.detection_type not in conditions['detection_types']:
                return False
        
        # Check frequency range
        if 'frequency_range' in conditions:
            freq_range = conditions['frequency_range']
            if not (freq_range[0] <= detection.frequency <= freq_range[1]):
                return False
        
        # Check for repeat detections
        if 'repeat_threshold' in conditions:
            similar_detections = self._count_similar_detections(detection, minutes=30)
            if similar_detections < conditions['repeat_threshold']:
                return False
        
        return True
    
    def _execute_response(self, rule, detection):
        """Execute automated response"""
        
        actions = rule.get('actions', [])
        
        for action in actions:
            try:
                if action['type'] == 'alert':
                    self._send_alert(action, detection)
                elif action['type'] == 'frequency_change':
                    self._request_frequency_change(action, detection)
                elif action['type'] == 'increase_monitoring':
                    self._increase_monitoring(action, detection)
                elif action['type'] == 'log_incident':
                    self._log_security_incident(action, detection)
                    
            except Exception as e:
                logger.error(f"Response action failed: {action['type']} - {e}")
    
    def _send_alert(self, action, detection):
        """Send immediate alert"""
        alert_msg = f"""
        HIGH PRIORITY RF SCANNER ALERT
        
        Detection Type: {detection.detection_type}
        Frequency: {detection.frequency/1e6:.3f} MHz
        Confidence: {detection.confidence:.2f}
        Signal Strength: {detection.signal_strength:.1f} dBm
        Time: {detection.timestamp}
        
        Automated Response: {action.get('message', 'Scanner detection threshold exceeded')}
        """
        
        # Always log the alert
        logger.warning(alert_msg)
    
    def _count_similar_detections(self, detection, minutes=30):
        """Count similar detections in time window"""
        # This would need to be implemented with access to detection database
        return 1  # Placeholder
    
    def _request_frequency_change(self, action, detection):
        """Log frequency change recommendation"""
        logger.warning(f"RECOMMENDATION: {action.get('recommendation', 'Consider frequency change')}")
    
    def _increase_monitoring(self, action, detection):
        """Log monitoring increase recommendation"""
        duration = action.get('duration_hours', 24)
        logger.warning(f"RECOMMENDATION: Increase monitoring for {duration} hours")
    
    def _log_security_incident(self, action, detection):
        """Log security incident"""
        severity = action.get('severity', 'MEDIUM')
        category = action.get('category', 'RF_DETECTION')
        logger.critical(f"SECURITY INCIDENT [{severity}] {category}: Scanner detected at {detection.frequency/1e6:.3f} MHz")

class SIEMIntegrator:
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
