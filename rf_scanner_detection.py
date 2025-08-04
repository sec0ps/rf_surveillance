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

import numpy as np
import threading
import time
import logging
import sqlite3
import json
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional
import queue
import hashlib
from scipy import signal
from scipy.fft import fft, fftfreq

try:
    from gnuradio import gr, blocks, analog
    try:
        from gnuradio import filter
    except ImportError:
        pass  # filter module might not be available in newer versions
    try:
        from gnuradio import fft
    except ImportError:
        pass  # fft module might be in different location
    from gnuradio import uhd
    import osmosdr
except ImportError:
    print("GNU Radio not installed. Install with: pip install gnuradio")
    raise

try:
    from sklearn.cluster import DBSCAN
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    print("scikit-learn not installed. Clustering features will be disabled.")
    print("Install with: pip install scikit-learn")
    SKLEARN_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    print("requests not installed. SIEM integration will be disabled.")
    print("Install with: pip install requests")
    REQUESTS_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('rf_scanner_detection.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class RFDetection:
    """Data structure for RF detection events"""
    timestamp: datetime
    frequency: float
    signal_strength: float
    detection_type: str  # 'scanning', 'targeted', 'active_probe', 'passive_listen'
    confidence: float
    duration: float
    metadata: Dict

@dataclass
class ScanPattern:
    """Pattern analysis for scanner detection"""
    frequency_hops: List[Tuple[float, float]]  # (freq, timestamp)
    hop_rate: float
    dwell_times: List[float]
    signal_strengths: List[float]
    pattern_type: str

class RFSpectrumAnalyzer:
    def __init__(self, sample_rate=2e6, fft_size=1024):
        self.sample_rate = sample_rate
        self.fft_size = fft_size
        self.frequency_history = defaultdict(deque)
        self.signal_threshold = -70  # dBm threshold for signal detection
        self.scan_detection_window = 30  # seconds
        
        # Pattern detection parameters
        self.min_hop_rate = 8  # Increased from 5 - hops per second to consider scanning
        self.max_dwell_time = 2.0  # seconds before considering targeted
        self.active_probe_threshold = -20  # Increased from -40 - dBm for active transmission detection
        
        # Calibration period - ignore detections for first 30 seconds
        self.start_time = datetime.now()
        self.calibration_period = 30  # seconds
    
        self.device_tracking = {}
        
        # ADD THESE ADVANCED COMPONENTS:
        self.signature_database = {}
        self.scanner_fingerprints = {}
        self.known_scanner_signatures = {}
        self.ioc_database = {}

    def analyze_spectrum(self, fft_data: np.ndarray, center_freq: float) -> List[RFDetection]:
        """Analyze FFT data for scanning patterns with enhanced fingerprinting"""
        detections = []
        current_time = datetime.now()
        
        # Skip detection during calibration period
        if (current_time - self.start_time).total_seconds() < self.calibration_period:
            logger.debug("Calibration period - skipping detection")
            return detections
        
        # Convert FFT to power spectrum
        power_spectrum = 20 * np.log10(np.abs(fft_data) + 1e-12)
        freqs = np.fft.fftfreq(len(fft_data), 1/self.sample_rate) + center_freq
        
        # Detect signals above threshold
        signal_indices = np.where(power_spectrum > self.signal_threshold)[0]
        
        for idx in signal_indices:
            freq = freqs[idx]
            power = power_spectrum[idx]
            
            # Update frequency history
            self.frequency_history[freq].append((current_time, power))
            
            # Keep only recent history
            cutoff_time = current_time - timedelta(seconds=self.scan_detection_window)
            while (self.frequency_history[freq] and 
                   self.frequency_history[freq][0][0] < cutoff_time):
                self.frequency_history[freq].popleft()
        
        # Analyze patterns for scanner detection
        detections.extend(self._detect_scanning_patterns(current_time))
        detections.extend(self._detect_targeted_monitoring(current_time))
        detections.extend(self._detect_active_probes(power_spectrum, freqs, current_time))
        
        # Generate enhanced fingerprints for ALL detections
        for detection in detections:
            fingerprint = self.generate_enhanced_fingerprint(fft_data, center_freq, detection.metadata)
            detection.metadata['enhanced_fingerprint'] = fingerprint
            
            # Store for device tracking
            device_id = fingerprint.get('device_id')
            if device_id:
                self._update_device_tracking(device_id, fingerprint, detection)
        
        return detections

    def _detect_scanning_patterns(self, current_time: datetime) -> List[RFDetection]:
        """Detect rapid frequency hopping patterns characteristic of scanners"""
        detections = []
        
        # Look for rapid frequency changes
        recent_freqs = []
        cutoff_time = current_time - timedelta(seconds=5)  # 5-second window
        
        for freq, history in self.frequency_history.items():
            recent_entries = [entry for entry in history if entry[0] > cutoff_time]
            if recent_entries:
                recent_freqs.append((freq, len(recent_entries), recent_entries[-1][1]))
        
        # Filter out our own sweeping behavior
        # If we're seeing signals across the entire FFT bandwidth, it's likely our own sweep
        if len(recent_freqs) > self.min_hop_rate * 5:  # 5-second window
            
            # Check if this looks like our own frequency sweep
            frequencies = [freq for freq, _, _ in recent_freqs]
            freq_span = max(frequencies) - min(frequencies)
            
            # If frequency span is close to our sample rate, it's likely our own FFT
            if freq_span >= self.sample_rate * 0.8:  # 80% of sample rate span
                logger.debug("Ignoring detection - appears to be own frequency sweep")
                return detections
            
            # Check for legitimate scanner patterns
            # Real scanners typically hop between discrete channels, not continuous spectrum
            freq_array = np.array(frequencies)
            freq_diffs = np.diff(np.sort(freq_array))
            
            # Look for regular channel spacing (typical of scanners)
            if len(freq_diffs) > 0:
                common_steps = []
                for step_size in [12.5e3, 25e3, 50e3, 100e3]:  # Common channel spacings
                    close_matches = np.abs(freq_diffs - step_size) < step_size * 0.1
                    if np.sum(close_matches) > len(freq_diffs) * 0.5:  # >50% match
                        common_steps.append(step_size)
            
                # Only detect if we see regular channel spacing patterns
                if common_steps:
                    hop_rate = len(recent_freqs) / 5.0
                    avg_power = np.mean([power for _, _, power in recent_freqs])
                    
                    # Additional validation - check if signals are strong enough to be real
                    strong_signals = [power for _, _, power in recent_freqs if power > -60]
                    if len(strong_signals) >= 3:  # At least 3 strong signals
                        detection = RFDetection(
                            timestamp=current_time,
                            frequency=np.mean(frequencies),  # Average frequency instead of 0
                            signal_strength=avg_power,
                            detection_type='scanning',
                            confidence=min(0.95, hop_rate / 50.0),  # Adjusted confidence calculation
                            duration=5.0,
                            metadata={
                                'hop_rate': hop_rate,
                                'frequencies_detected': len(recent_freqs),
                                'frequency_range': (min(frequencies), max(frequencies)),
                                'channel_spacing': common_steps[0] if common_steps else 0,
                                'strong_signals': len(strong_signals)
                            }
                        )
                        detections.append(detection)
                        logger.warning(f"Scanner detected: {hop_rate:.1f} hops/sec across {len(recent_freqs)} frequencies")
        
        return detections
    
    def _detect_targeted_monitoring(self, current_time: datetime) -> List[RFDetection]:
        """Detect sustained monitoring of specific frequencies"""
        detections = []
        
        for freq, history in self.frequency_history.items():
            if len(history) < 3:  # Need multiple samples
                continue
                
            # Calculate dwell time and signal consistency
            time_span = (history[-1][0] - history[0][0]).total_seconds()
            if time_span > self.max_dwell_time:
                signal_powers = [power for _, power in history]
                power_variance = np.var(signal_powers)
                avg_power = np.mean(signal_powers)
                
                # Low variance + sustained presence suggests monitoring
                if power_variance < 5.0 and time_span > 10:  # 10 second minimum
                    confidence = min(0.9, time_span / 60.0)  # Longer time = higher confidence
                    
                    detection = RFDetection(
                        timestamp=current_time,
                        frequency=freq,
                        signal_strength=avg_power,
                        detection_type='targeted',
                        confidence=confidence,
                        duration=time_span,
                        metadata={
                            'dwell_time': time_span,
                            'power_variance': power_variance,
                            'sample_count': len(history)
                        }
                    )
                    detections.append(detection)
                    logger.warning(f"Targeted monitoring detected on {freq/1e6:.3f} MHz for {time_span:.1f}s")
        
        return detections

    def _detect_active_probes(self, power_spectrum: np.ndarray, freqs: np.ndarray, current_time: datetime) -> List[RFDetection]:
        """Detect active RF probes/transmissions that might be scanner-generated"""
        detections = []
        
        # Look for strong, brief signals that might be active probes
        strong_signals = np.where(power_spectrum > self.active_probe_threshold)[0]
        
        # Additional filtering to reduce false positives
        if len(strong_signals) == 0:
            return detections
        
        # Calculate noise floor to distinguish real signals from noise
        noise_floor = np.percentile(power_spectrum, 10)  # 10th percentile as noise estimate
        dynamic_threshold = noise_floor + 30  # Signal must be 30 dB above noise floor
        
        # Apply dynamic threshold
        strong_signals = np.where(power_spectrum > max(self.active_probe_threshold, dynamic_threshold))[0]
        
        # Limit detections to prevent spam
        if len(strong_signals) > 10:  # If too many signals, likely interference
            # Only take the strongest signals
            signal_powers = power_spectrum[strong_signals]
            top_indices = np.argsort(signal_powers)[-5:]  # Top 5 strongest
            strong_signals = strong_signals[top_indices]
        
        for idx in strong_signals:
            freq = freqs[idx]
            power = power_spectrum[idx]
            
            # Additional validation - skip if signal is too consistent (likely legitimate transmission)
            if self._is_likely_legitimate_signal(freq, power):
                continue
            
            # Calculate confidence based on signal characteristics
            confidence = self._calculate_probe_confidence(power, noise_floor, freq)
            
            # Only create detection if confidence is reasonable
            if confidence > 0.5:
                detection = RFDetection(
                    timestamp=current_time,
                    frequency=freq,
                    signal_strength=power,
                    detection_type='active_probe',
                    confidence=confidence,
                    duration=0.1,  # Brief probe
                    metadata={
                        'probe_power': power,
                        'above_threshold': power - self.active_probe_threshold,
                        'above_noise_floor': power - noise_floor,
                        'noise_floor': noise_floor
                    }
                )
                detections.append(detection)
        
        return detections

    def _is_likely_legitimate_signal(self, freq: float, power: float) -> bool:
        """Check if signal is likely a legitimate transmission rather than a probe"""
        
        # Check if frequency is in a known legitimate band
        legitimate_bands = [
            (88e6, 108e6),    # FM Broadcast
            (118e6, 137e6),   # Aviation
            (162e6, 174e6),   # Weather/Emergency
            (470e6, 890e6),   # TV/Cellular
        ]
        
        for start, end in legitimate_bands:
            if start <= freq <= end:
                return True
        
        # Check signal history for consistency (legitimate signals tend to be more stable)
        if freq in self.frequency_history:
            recent_powers = [p for _, p in list(self.frequency_history[freq])[-5:]]
            if len(recent_powers) >= 3:
                power_variance = np.var(recent_powers)
                if power_variance < 2.0:  # Low variance suggests legitimate transmission
                    return True
        
        return False
    
    def _calculate_probe_confidence(self, power: float, noise_floor: float, freq: float) -> float:
        """Calculate confidence that this is an active probe"""
        
        # Base confidence on signal strength above noise floor
        snr = power - noise_floor
        base_confidence = min(0.8, snr / 40.0)  # Max confidence 0.8 for active probes
        
        # Reduce confidence if signal is too strong (likely legitimate transmitter)
        if power > 10:  # Very strong signals are usually legitimate
            base_confidence *= 0.3
        
        # Reduce confidence for known legitimate frequencies
        if self._is_likely_legitimate_signal(freq, power):
            base_confidence *= 0.2
        
        return max(0.0, min(1.0, base_confidence))

    def _update_device_tracking(self, device_id: str, fingerprint: Dict, detection: RFDetection):
        """Update device tracking database"""
        
        if not hasattr(self, 'device_tracking'):
            self.device_tracking = {}
        
        if device_id not in self.device_tracking:
            self.device_tracking[device_id] = {
                'first_seen': detection.timestamp,
                'last_seen': detection.timestamp,
                'detection_count': 0,
                'fingerprint_evolution': [],
                'behavior_patterns': []
            }
        
        # Update tracking info
        tracking = self.device_tracking[device_id]
        tracking['last_seen'] = detection.timestamp
        tracking['detection_count'] += 1
        tracking['fingerprint_evolution'].append({
            'timestamp': detection.timestamp,
            'fingerprint': fingerprint
        })
        tracking['behavior_patterns'].append({
            'detection_type': detection.detection_type,
            'confidence': detection.confidence,
            'metadata': detection.metadata
        })
        
        # Keep only recent data (last 100 entries)
        if len(tracking['fingerprint_evolution']) > 100:
            tracking['fingerprint_evolution'] = tracking['fingerprint_evolution'][-100:]
        if len(tracking['behavior_patterns']) > 100:
            tracking['behavior_patterns'] = tracking['behavior_patterns'][-100:]
    
    def get_tracked_devices(self) -> Dict:
        """Get summary of tracked devices"""
        
        if not hasattr(self, 'device_tracking'):
            return {}
        
        summary = {}
        for device_id, tracking in self.device_tracking.items():
            summary[device_id] = {
                'first_seen': tracking['first_seen'].isoformat(),
                'last_seen': tracking['last_seen'].isoformat(),
                'detection_count': tracking['detection_count'],
                'active_duration': str(tracking['last_seen'] - tracking['first_seen']),
                'primary_behavior': self._analyze_primary_behavior(tracking['behavior_patterns'])
            }
        
        return summary

    def _extract_spectral_mask(self, power_spectrum: np.ndarray) -> Dict:
        """Extract spectral mask characteristics"""
        # Find the main signal shape
        peak_idx = np.argmax(power_spectrum)
        peak_power = power_spectrum[peak_idx]
        
        # Analyze spectral mask at different levels
        mask_levels = [-3, -20, -40, -60]  # dB below peak
        mask_points = {}
        
        for level in mask_levels:
            threshold = peak_power + level
            above_threshold = np.where(power_spectrum > threshold)[0]
            if len(above_threshold) > 0:
                bandwidth = above_threshold[-1] - above_threshold[0]
                mask_points[f'mask_{abs(level)}db'] = bandwidth
        
        return mask_points
    
    def _classify_scan_pattern(self, detection_metadata: Dict) -> str:
        """Classify scan pattern type"""
        hop_rate = detection_metadata.get('hop_rate', 0)
        freq_count = detection_metadata.get('frequencies_detected', 0)
        
        if hop_rate > 100:
            return 'high_speed_scan'
        elif hop_rate > 20:
            return 'medium_speed_scan'
        elif freq_count > hop_rate * 2:
            return 'wide_range_scan'
        else:
            return 'sequential_scan'
    
    def _analyze_dwell_time_pattern(self, detection_metadata: Dict) -> str:
        """Analyze dwell time consistency"""
        # This would analyze the consistency of dwell times
        # For now, return a basic assessment
        return 'consistent'
    
    def _analyze_monitoring_pattern(self, detection_metadata: Dict) -> str:
        """Analyze monitoring pattern for targeted detection"""
        dwell_time = detection_metadata.get('dwell_time', 0)
        power_variance = detection_metadata.get('power_variance', 0)
        
        if power_variance < 1.0 and dwell_time > 60:
            return 'sustained_monitoring'
        elif dwell_time > 10:
            return 'brief_monitoring'
        else:
            return 'intermittent_monitoring'
    
    def _calculate_rolloff_rate(self, power_spectrum: np.ndarray, above_half_power: np.ndarray) -> float:
        """Calculate filter rolloff rate"""
        if len(above_half_power) == 0:
            return 0
        
        # Calculate rolloff on both sides of the passband
        center_idx = len(power_spectrum) // 2
        left_edge = above_half_power[0]
        right_edge = above_half_power[-1]
        
        # Estimate rolloff rate (dB per bin)
        if left_edge > 0 and right_edge < len(power_spectrum) - 1:
            left_rolloff = power_spectrum[left_edge] - power_spectrum[left_edge - 10] if left_edge >= 10 else 0
            right_rolloff = power_spectrum[right_edge] - power_spectrum[right_edge + 10] if right_edge <= len(power_spectrum) - 11 else 0
            return (left_rolloff + right_rolloff) / 2
        
        return 0

    def _analyze_primary_behavior(self, behavior_patterns: List[Dict]) -> str:
        """Analyze primary behavior pattern of a device"""
        
        if not behavior_patterns:
            return 'unknown'
        
        # Count detection types
        type_counts = {}
        for pattern in behavior_patterns:
            det_type = pattern['detection_type']
            type_counts[det_type] = type_counts.get(det_type, 0) + 1
        
        # Return most common behavior
        return max(type_counts, key=type_counts.get)

    def generate_enhanced_fingerprint(self, fft_data: np.ndarray, center_freq: float, detection_metadata: Dict) -> Dict:
        """Generate enhanced fingerprint for unique scanner identification"""
        
        fingerprint = {
            'timestamp': datetime.now().isoformat(),
            'center_frequency': center_freq,
            'sample_rate': self.sample_rate
        }
        
        try:
            # Hardware signature analysis
            fingerprint.update(self._analyze_hardware_signature(fft_data))
            
            # Timing characteristics
            fingerprint.update(self._analyze_timing_patterns(detection_metadata))
            
            # Spectral uniqueness
            fingerprint.update(self._analyze_spectral_uniqueness(fft_data))
            
            # Scanner behavior patterns
            fingerprint.update(self._analyze_scanner_behavior(detection_metadata))
            
            # Generate unique device ID
            fingerprint['device_id'] = self._generate_device_id(fingerprint)
            
            # ADD ENHANCED CLASSIFICATION:
            fingerprint['scanner_classification'] = self._classify_scanner_from_fingerprint(fingerprint, detection_metadata)
            fingerprint['equipment_type'] = self._determine_equipment_type(fingerprint)
            fingerprint['sophistication_level'] = self._assess_sophistication_level(fingerprint)
            
            # ADD ADVANCED CLUSTERING ANALYSIS:
            # Perform signature clustering if we have enough signatures
            signature_list = list(self.scanner_fingerprints.values())
            if len(signature_list) >= 3:
                cluster_analysis = self.cluster_scanner_signatures(signature_list)
                fingerprint['cluster_analysis'] = cluster_analysis
                
                # Update device classification based on clustering
                if cluster_analysis['n_clusters'] > 0:
                    fingerprint['device_classification'] = self._classify_device_from_fingerprint(fingerprint, cluster_analysis)
            
            # ADD SIGNATURE MATCHING:
            # Match against known scanner database
            signature_matches = self.match_signature_against_database(fingerprint)
            fingerprint['signature_matches'] = signature_matches
            
            # Store fingerprint for future clustering
            device_id = fingerprint.get('device_id')
            if device_id:
                self.scanner_fingerprints[device_id] = fingerprint
            
            # ADD IOC GENERATION:
            # Generate IOC if this is a significant detection
            if detection_metadata.get('confidence', 0) > 0.7:
                ioc = self.generate_ioc_from_fingerprint(fingerprint, detection_metadata)
                fingerprint['threat_ioc'] = ioc
                
        except Exception as e:
            logger.error(f"Fingerprinting error: {e}")
            fingerprint['error'] = str(e)
        
        return fingerprint
    
    def _classify_scanner_from_fingerprint(self, fingerprint: Dict, detection_metadata: Dict) -> str:
        """Classify scanner type from complete fingerprint"""
        
        # Hardware characteristics
        adc_bits = fingerprint.get('estimated_adc_bits', 8)
        clock_precision = fingerprint.get('clock_precision_ppm', 1000)
        phase_noise = fingerprint.get('lo_phase_noise_db', 0)
        
        # Behavioral characteristics
        detection_type = detection_metadata.get('detection_type', '')
        hop_rate = detection_metadata.get('hop_rate', 0)
        channel_spacing = detection_metadata.get('channel_spacing', 0)
        
        # Professional equipment indicators
        if adc_bits >= 14 and clock_precision <= 10 and phase_noise < -120:
            if hop_rate > 100:
                return "Professional High-Speed Scanner"
            else:
                return "Professional Surveillance Receiver"
        
        # Commercial equipment
        elif adc_bits >= 12 and clock_precision <= 100:
            if detection_type == 'scanning':
                if channel_spacing == 12500:
                    return "Commercial Narrowband Scanner"
                elif channel_spacing == 25000:
                    return "Commercial Wideband Scanner"
                else:
                    return "Commercial Digital Scanner"
            else:
                return "Commercial Monitoring Receiver"
        
        # Consumer equipment
        elif adc_bits >= 8:
            if hop_rate > 0 and hop_rate < 20:
                return "Consumer Analog Scanner"
            else:
                return "Consumer Digital Scanner"
        
        # SDR-based
        if fingerprint.get('frequency_response_flatness', 0) > 8:
            return "SDR-Based Scanner (RTL-SDR/HackRF)"
        
        return "Unidentified Scanner Type"
    
    def _determine_equipment_type(self, fingerprint: Dict) -> str:
        """Determine broad equipment category"""
        
        adc_bits = fingerprint.get('estimated_adc_bits', 8)
        image_rejection = fingerprint.get('image_rejection_db', 0)
        spurious_count = fingerprint.get('spurious_count', 0)
        
        if adc_bits >= 14 and image_rejection > 60 and spurious_count < 2:
            return "Professional Communications Equipment"
        elif adc_bits >= 12 and image_rejection > 40:
            return "Commercial Radio Equipment"
        elif spurious_count > 5:
            return "Consumer/Hobby Equipment"
        else:
            return "Unknown Equipment Type"
    
    def _assess_sophistication_level(self, fingerprint: Dict) -> str:
        """Assess overall sophistication level"""
        
        sophistication_score = 0
        
        # Hardware sophistication
        if fingerprint.get('estimated_adc_bits', 8) >= 14:
            sophistication_score += 3
        elif fingerprint.get('estimated_adc_bits', 8) >= 12:
            sophistication_score += 2
        elif fingerprint.get('estimated_adc_bits', 8) >= 10:
            sophistication_score += 1
        
        # Clock precision
        clock_ppm = fingerprint.get('clock_precision_ppm', 1000)
        if clock_ppm <= 1:
            sophistication_score += 3
        elif clock_ppm <= 10:
            sophistication_score += 2
        elif clock_ppm <= 100:
            sophistication_score += 1
        
        # Phase noise performance
        phase_noise = fingerprint.get('lo_phase_noise_db', 0)
        if phase_noise < -130:
            sophistication_score += 3
        elif phase_noise < -120:
            sophistication_score += 2
        elif phase_noise < -110:
            sophistication_score += 1
        
        # Image rejection
        image_rejection = fingerprint.get('image_rejection_db', 0)
        if image_rejection > 80:
            sophistication_score += 2
        elif image_rejection > 60:
            sophistication_score += 1
        
        # Classify based on total score
        if sophistication_score >= 8:
            return "Military/Intelligence Grade"
        elif sophistication_score >= 6:
            return "Professional Grade"
        elif sophistication_score >= 4:
            return "Commercial Grade"
        elif sophistication_score >= 2:
            return "Consumer Grade"
        else:
            return "Entry Level"

    def cluster_scanner_signatures(self, signatures: List[Dict]) -> Dict:
        """Cluster similar scanner signatures to identify device types"""
        
        if len(signatures) < 3:
            return {'clusters': [], 'device_types': [], 'n_clusters': 0}
        
        # Check if sklearn is available
        if not SKLEARN_AVAILABLE:
            logger.warning("scikit-learn not available - clustering disabled")
            return {
                'clusters': {},
                'cluster_labels': [],
                'n_clusters': 0,
                'error': 'scikit-learn not installed'
            }
        
        try:
            # Convert signatures to feature matrix
            features = []
            for sig in signatures:
                feature_vector = [
                    sig.get('dc_offset', 0),
                    sig.get('frequency_response_flatness', 0), 
                    sig.get('phase_noise_profile', {}).get('pn_1khz', 0),
                    sig.get('estimated_adc_bits', 8),
                    sig.get('lo_phase_noise_db', 0),
                    sig.get('clock_precision_ppm', 1000)
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
                    'centroid': np.mean(cluster_features, axis=0).tolist(),
                    'std': np.std(cluster_features, axis=0).tolist(),
                    'device_type': self._classify_device_from_cluster(np.mean(cluster_features, axis=0))
                }
            
            return {
                'clusters': cluster_analysis,
                'cluster_labels': cluster_labels.tolist(),
                'n_clusters': len(unique_clusters) - (1 if -1 in unique_clusters else 0)
            }
            
        except Exception as e:
            logger.error(f"Clustering error: {e}")
            return {
                'clusters': {},
                'cluster_labels': [],
                'n_clusters': 0,
                'error': str(e)
            }
    
    def _classify_device_from_cluster(self, feature_centroid: np.ndarray) -> str:
        """Classify scanner device type based on signature"""
        
        dc_offset, flatness, phase_noise, adc_bits, lo_noise, clock_ppm = feature_centroid
        
        # Classification rules based on typical scanner characteristics
        if phase_noise < -120 and adc_bits >= 14 and clock_ppm <= 10:
            return "Professional SDR Scanner"
        elif lo_noise < -110 and adc_bits >= 12 and clock_ppm <= 100:
            return "Commercial Digital Scanner"
        elif adc_bits >= 10 and clock_ppm <= 1000:
            return "Consumer Analog Scanner"
        elif flatness > 10:
            return "Wideband Scanner (SDR-based)"
        else:
            return "Unknown Scanner Type"
    
    def match_signature_against_database(self, observed_signature: Dict) -> List[Dict]:
        """Match observed signature against known scanner database"""
        matches = []
        
        # Load known signatures if not already loaded
        if not self.known_scanner_signatures:
            self._load_default_scanner_signatures()
        
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
    
    def _load_default_scanner_signatures(self):
        """Load default known scanner signatures"""
        self.known_scanner_signatures = {
            'uniden_bc125at': {
                'dc_offset': -45.0,
                'estimated_adc_bits': 12,
                'clock_precision_ppm': 100,
                'lo_phase_noise_db': -105,
                'frequency_response_flatness': 3.5
            },
            'rtlsdr_generic': {
                'dc_offset': -40.0,
                'estimated_adc_bits': 8,
                'clock_precision_ppm': 1000,
                'lo_phase_noise_db': -95,
                'frequency_response_flatness': 8.0
            },
            'hackrf_one': {
                'dc_offset': -42.0,
                'estimated_adc_bits': 8,
                'clock_precision_ppm': 20,
                'lo_phase_noise_db': -100,
                'frequency_response_flatness': 5.0
            },
            'professional_scanner': {
                'dc_offset': -50.0,
                'estimated_adc_bits': 14,
                'clock_precision_ppm': 10,
                'lo_phase_noise_db': -120,
                'frequency_response_flatness': 2.0
            }
        }
    
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
    
    def generate_ioc_from_fingerprint(self, fingerprint: Dict, detection_data: Dict) -> Dict:
        """Generate Indicator of Compromise from fingerprint and detection"""
        
        # Create unique IOC hash based on signature
        signature_str = str(sorted(fingerprint.items()))
        ioc_hash = hashlib.sha256(signature_str.encode()).hexdigest()[:16]
        
        ioc = {
            'id': f"RF_SCAN_{ioc_hash}",
            'type': 'rf_scanner_detection',
            'first_seen': detection_data.get('timestamp', datetime.now().isoformat()),
            'last_seen': detection_data.get('timestamp', datetime.now().isoformat()),
            'device_id': fingerprint.get('device_id'),
            'confidence': detection_data.get('confidence', 0),
            'signature_hash': ioc_hash,
            'threat_level': self._classify_ioc_threat_level(detection_data, fingerprint),
            'attributes': {
                'detection_type': detection_data.get('detection_type'),
                'estimated_hardware': fingerprint.get('device_classification', 'Unknown'),
                'scanner_matches': fingerprint.get('signature_matches', [])
            }
        }
        
        self.ioc_database[ioc['id']] = ioc
        return ioc
    
    def _classify_ioc_threat_level(self, detection_data: Dict, fingerprint: Dict) -> str:
        """Classify IOC threat level based on detection and fingerprint characteristics"""
        confidence = detection_data.get('confidence', 0)
        detection_type = detection_data.get('detection_type', '')
        
        # Hardware sophistication factor
        adc_bits = fingerprint.get('estimated_adc_bits', 8)
        clock_precision = fingerprint.get('clock_precision_ppm', 1000)
        
        if confidence > 0.9 and detection_type == 'targeted' and adc_bits >= 14 and clock_precision <= 10:
            return 'CRITICAL'
        elif confidence > 0.8 and detection_type in ['scanning', 'targeted'] and adc_bits >= 12:
            return 'HIGH'
        elif confidence > 0.6 and detection_type in ['scanning', 'targeted']:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _classify_device_from_fingerprint(self, fingerprint: Dict, cluster_analysis: Dict) -> str:
        """Classify device based on fingerprint and cluster analysis"""
        
        # Check if device falls into a known cluster
        device_id = fingerprint.get('device_id')
        clusters = cluster_analysis.get('clusters', {})
        
        for cluster_id, cluster_info in clusters.items():
            device_type = cluster_info.get('device_type', 'Unknown')
            if device_type != 'Unknown Scanner Type':
                return device_type
        
        # Fallback to individual analysis
        adc_bits = fingerprint.get('estimated_adc_bits', 8)
        clock_precision = fingerprint.get('clock_precision_ppm', 1000)
        
        if adc_bits >= 14 and clock_precision <= 10:
            return "Professional Equipment"
        elif adc_bits >= 12 and clock_precision <= 100:
            return "Commercial Equipment"
        else:
            return "Consumer Equipment"
    
    def _analyze_hardware_signature(self, fft_data: np.ndarray) -> Dict:
        """Analyze hardware-specific characteristics"""
        
        power_spectrum = 20 * np.log10(np.abs(fft_data) + 1e-12)
        
        # DC offset (indicates mixer/ADC characteristics)
        dc_bin = len(fft_data) // 2
        dc_offset = power_spectrum[dc_bin]
        
        # Harmonic distortion analysis
        harmonics = self._find_harmonics(power_spectrum)
        
        # Image rejection (if present)
        image_rejection = self._calculate_image_rejection(power_spectrum)
        
        # Spurious signals (clock leakage, etc.)
        spurs = self._detect_spurious_signals(power_spectrum)
        
        # Frequency response flatness
        flatness = np.std(power_spectrum[power_spectrum > -80])  # Only analyze above noise floor
        
        return {
            'dc_offset': dc_offset,
            'harmonic_distortion': harmonics,
            'image_rejection_db': image_rejection,
            'spurious_count': len(spurs),
            'frequency_response_flatness': flatness,
            'bandwidth_shape': self._analyze_bandwidth_shape(power_spectrum)
        }
    
    def _analyze_timing_patterns(self, detection_metadata: Dict) -> Dict:
        """Analyze timing characteristics unique to scanner hardware"""
        
        timing_sig = {}
        
        if detection_metadata.get('detection_type') == 'scanning':
            hop_rate = detection_metadata.get('hop_rate', 0)
            
            # Clock precision analysis
            if hop_rate > 0:
                # Calculate timing jitter from hop rate variations
                timing_sig['hop_rate_stability'] = self._calculate_hop_rate_stability(hop_rate)
                timing_sig['clock_precision_ppm'] = self._estimate_clock_precision(hop_rate)
            
            # Scan pattern analysis
            freq_range = detection_metadata.get('frequency_range', (0, 0))
            channel_spacing = detection_metadata.get('channel_spacing', 0)
            
            if channel_spacing > 0:
                timing_sig['channel_step_precision'] = channel_spacing
                timing_sig['scan_algorithm'] = self._classify_scan_algorithm(detection_metadata)
        
        return timing_sig
    
    def _analyze_spectral_uniqueness(self, fft_data: np.ndarray) -> Dict:
        """Analyze spectral characteristics unique to specific hardware"""
        
        power_spectrum = 20 * np.log10(np.abs(fft_data) + 1e-12)
        
        # Spectral mask (unique filter characteristics)
        spectral_mask = self._extract_spectral_mask(power_spectrum)
        
        # Phase noise profile
        phase_data = np.angle(fft_data)
        phase_noise_profile = self._analyze_phase_noise_profile(phase_data)
        
        # ADC bit depth estimation
        estimated_bits = self._estimate_adc_bits(fft_data)
        
        # Local oscillator characteristics
        lo_characteristics = self._analyze_lo_characteristics(fft_data)
        
        return {
            'spectral_mask_signature': spectral_mask,
            'phase_noise_profile': phase_noise_profile,
            'estimated_adc_bits': estimated_bits,
            'lo_phase_noise_db': lo_characteristics['phase_noise'],
            'lo_frequency_accuracy_ppm': lo_characteristics['frequency_accuracy']
        }
    
    def _analyze_scanner_behavior(self, detection_metadata: Dict) -> Dict:
        """Analyze behavioral patterns specific to scanner software/firmware"""
        
        behavior = {}
        
        # Scan pattern regularity
        if detection_metadata.get('detection_type') == 'scanning':
            behavior['scan_pattern_type'] = self._classify_scan_pattern(detection_metadata)
            behavior['dwell_time_consistency'] = self._analyze_dwell_time_pattern(detection_metadata)
            
            # Memory scan vs programmed scan detection
            hop_rate = detection_metadata.get('hop_rate', 0)
            freq_count = detection_metadata.get('frequencies_detected', 0)
            
            if hop_rate > 0 and freq_count > 0:
                scan_efficiency = freq_count / (hop_rate * 5)  # 5 second window
                behavior['scan_efficiency'] = scan_efficiency
                
                if scan_efficiency > 0.8:
                    behavior['scan_type'] = 'programmed_channels'
                elif scan_efficiency < 0.3:
                    behavior['scan_type'] = 'memory_scan'
                else:
                    behavior['scan_type'] = 'search_mode'
        
        elif detection_metadata.get('detection_type') == 'targeted':
            behavior['monitoring_consistency'] = self._analyze_monitoring_pattern(detection_metadata)
            
        return behavior
    
    def _generate_device_id(self, fingerprint: Dict) -> str:
        """Generate unique device identifier from fingerprint"""
        
        # Extract key characteristics for unique ID
        key_features = [
            fingerprint.get('dc_offset', 0),
            fingerprint.get('frequency_response_flatness', 0),
            fingerprint.get('estimated_adc_bits', 0),
            fingerprint.get('lo_phase_noise_db', 0),
            fingerprint.get('clock_precision_ppm', 0)
        ]
        
        # Create hash from key features
        feature_string = '_'.join([f"{x:.6f}" for x in key_features])
        device_hash = hashlib.sha256(feature_string.encode()).hexdigest()[:16]
        
        return f"RF_SCANNER_{device_hash}"
    
    def _find_harmonics(self, power_spectrum: np.ndarray) -> Dict:
        """Find harmonic distortion products"""
        
        # Find fundamental frequency (strongest peak)
        fundamental_idx = np.argmax(power_spectrum)
        fundamental_power = power_spectrum[fundamental_idx]
        
        harmonics = {}
        
        # Look for 2nd and 3rd harmonics
        for harmonic in [2, 3]:
            harmonic_idx = (fundamental_idx * harmonic) % len(power_spectrum)
            harmonic_power = power_spectrum[harmonic_idx]
            
            if harmonic_power > fundamental_power - 60:  # Within 60dB
                harmonics[f'harmonic_{harmonic}_db'] = harmonic_power - fundamental_power
        
        return harmonics
    
    def _calculate_image_rejection(self, power_spectrum: np.ndarray) -> float:
        """Calculate image rejection ratio"""
        
        center_idx = len(power_spectrum) // 2
        
        # Look for image frequencies (mirror around center)
        image_rejection = 0
        count = 0
        
        for offset in range(10, min(50, center_idx)):
            signal_power = power_spectrum[center_idx + offset]
            image_power = power_spectrum[center_idx - offset]
            
            if signal_power > -80:  # Only analyze strong signals
                rejection = signal_power - image_power
                image_rejection += rejection
                count += 1
        
        return image_rejection / count if count > 0 else 0

    def _detect_spurious_signals(self, power_spectrum: np.ndarray) -> List[Dict]:
        """Detect spurious signals (clock harmonics, etc.)"""
        
        # Find peaks above noise floor
        noise_floor = np.percentile(power_spectrum, 10)
        threshold = noise_floor + 20  # 20dB above noise
        
        from scipy import signal
        peaks, properties = signal.find_peaks(power_spectrum, height=threshold, distance=5)
        
        spurs = []
        for peak_idx in peaks:
            spur_power = power_spectrum[peak_idx]
            frequency_bin = peak_idx
            
            spurs.append({
                'frequency_bin': frequency_bin,
                'power_db': spur_power,
                'above_noise': spur_power - noise_floor
            })
        
        return spurs
    
    def _analyze_bandwidth_shape(self, power_spectrum: np.ndarray) -> Dict:
        """Analyze the shape of the frequency response"""
        
        # Find -3dB bandwidth
        peak_power = np.max(power_spectrum)
        half_power = peak_power - 3
        
        above_half_power = np.where(power_spectrum > half_power)[0]
        
        if len(above_half_power) > 0:
            bandwidth_bins = above_half_power[-1] - above_half_power[0]
            bandwidth_hz = bandwidth_bins * (self.sample_rate / len(power_spectrum))
            
            # Analyze shape factor (ratio of -60dB to -3dB bandwidth)
            sixty_db_down = peak_power - 60
            above_sixty_db = np.where(power_spectrum > sixty_db_down)[0]
            
            if len(above_sixty_db) > 0:
                sixty_db_bandwidth = above_sixty_db[-1] - above_sixty_db[0]
                shape_factor = sixty_db_bandwidth / bandwidth_bins if bandwidth_bins > 0 else 0
            else:
                shape_factor = 0
            
            return {
                'bandwidth_3db_hz': bandwidth_hz,
                'shape_factor': shape_factor,
                'rolloff_rate': self._calculate_rolloff_rate(power_spectrum, above_half_power)
            }
        
        return {'bandwidth_3db_hz': 0, 'shape_factor': 0, 'rolloff_rate': 0}

    def _calculate_hop_rate_stability(self, hop_rate: float) -> float:
        """Calculate stability of hop rate (indicates clock quality)"""
        
        # Store hop rate measurements for stability analysis
        if not hasattr(self, 'hop_rate_history'):
            self.hop_rate_history = deque(maxlen=50)
        
        self.hop_rate_history.append(hop_rate)
        
        if len(self.hop_rate_history) >= 5:
            rates = list(self.hop_rate_history)
            stability = np.std(rates) / np.mean(rates) if np.mean(rates) > 0 else 1.0
            return stability
        
        return 1.0  # Unknown stability
    
    def _estimate_clock_precision(self, hop_rate: float) -> float:
        """Estimate clock precision in PPM"""
        
        # Typical scanner hop rates and their expected precision
        expected_rates = {
            'slow': (1, 5, 1000),      # 1-5 Hz, 1000 PPM (consumer)
            'medium': (5, 50, 100),    # 5-50 Hz, 100 PPM (prosumer)
            'fast': (50, 200, 10),     # 50-200 Hz, 10 PPM (professional)
            'very_fast': (200, 1000, 1) # >200 Hz, 1 PPM (SDR/high-end)
        }
        
        for category, (min_rate, max_rate, typical_ppm) in expected_rates.items():
            if min_rate <= hop_rate <= max_rate:
                return typical_ppm
        
        return 1000  # Default for unknown
    
    def _classify_scan_algorithm(self, detection_metadata: Dict) -> str:
        """Classify the scanning algorithm being used"""
        
        hop_rate = detection_metadata.get('hop_rate', 0)
        channel_spacing = detection_metadata.get('channel_spacing', 0)
        freq_count = detection_metadata.get('frequencies_detected', 0)
        
        if channel_spacing == 25000:  # 25 kHz
            return 'standard_fm_scan'
        elif channel_spacing == 12500:  # 12.5 kHz
            return 'narrowband_scan'
        elif channel_spacing == 6250:   # 6.25 kHz
            return 'digital_scan'
        elif hop_rate > 100:
            return 'fast_digital_scan'
        elif freq_count > hop_rate * 3:  # More frequencies than time allows
            return 'parallel_scan'
        else:
            return 'sequential_scan'

    def _analyze_phase_noise_profile(self, phase_data: np.ndarray) -> Dict:
        """Analyze phase noise characteristics"""
        
        # Remove linear phase trend
        phase_unwrapped = np.unwrap(phase_data)
        from scipy import signal
        phase_detrended = signal.detrend(phase_unwrapped)
        
        # Calculate phase noise PSD
        from scipy.fft import fft
        phase_psd = np.abs(fft(phase_detrended))**2
        freqs = np.fft.fftfreq(len(phase_data), 1/self.sample_rate)
        
        # Analyze at specific offset frequencies
        offset_freqs = [1e3, 10e3, 100e3]  # 1kHz, 10kHz, 100kHz offsets
        phase_noise_levels = {}
        
        for offset_freq in offset_freqs:
            freq_idx = np.argmin(np.abs(freqs - offset_freq))
            if freq_idx < len(phase_psd):
                phase_noise_levels[f'pn_{int(offset_freq/1000)}khz'] = 10 * np.log10(phase_psd[freq_idx])
        
        return phase_noise_levels
    
    def _estimate_adc_bits(self, fft_data: np.ndarray) -> int:
        """Estimate ADC bit depth from signal characteristics"""
        
        # Calculate theoretical SNR based on signal statistics
        signal_power = np.mean(np.abs(fft_data)**2)
        noise_power = np.var(np.real(fft_data)) + np.var(np.imag(fft_data))
        
        if noise_power > 0:
            snr_db = 10 * np.log10(signal_power / noise_power)
            
            # Theoretical: SNR ≈ 6.02 * N + 1.76 (where N is bit depth)
            estimated_bits = max(1, int((snr_db - 1.76) / 6.02))
            
            # Clamp to reasonable range
            return min(16, max(8, estimated_bits))
        
        return 12  # Default assumption
    
    def _analyze_lo_characteristics(self, fft_data: np.ndarray) -> Dict:
        """Analyze local oscillator characteristics"""
        
        # Frequency domain analysis
        power_spectrum = 20 * np.log10(np.abs(fft_data) + 1e-12)
        
        # LO leakage (DC component)
        dc_bin = len(fft_data) // 2
        lo_leakage = power_spectrum[dc_bin]
        
        # Phase noise estimate (from spectral width)
        peak_idx = np.argmax(power_spectrum)
        peak_power = power_spectrum[peak_idx]
        
        # Measure spectral width at -20dB from peak
        threshold = peak_power - 20
        above_threshold = np.where(power_spectrum > threshold)[0]
        
        if len(above_threshold) > 0:
            spectral_width = (above_threshold[-1] - above_threshold[0]) * (self.sample_rate / len(fft_data))
        else:
            spectral_width = 0
        
        return {
            'phase_noise': lo_leakage - peak_power,  # Relative to signal
            'frequency_accuracy': spectral_width / self.sample_rate * 1e6  # PPM
        }

class HackRFController:
    """HackRF device control and data acquisition"""
    
    def __init__(self, sample_rate=2e6, gain=20):
        self.sample_rate = sample_rate
        self.gain = gain
        self.center_freq = 400e6  # Starting frequency
        self.is_running = False
        self.data_queue = queue.Queue(maxsize=100)
        self.tb = None
        self.osmosdr_source = None
        self.stream_to_vector = None
        self.fft_block = None
        self.vector_sink = None
        
    def setup_flowgraph(self):
        """Setup GNU Radio flowgraph for HackRF"""
        try:
            self.tb = gr.top_block()
            
            # HackRF source
            self.osmosdr_source = osmosdr.source(args="numchan=1 hackrf=0")
            self.osmosdr_source.set_sample_rate(self.sample_rate)
            self.osmosdr_source.set_center_freq(self.center_freq)
            self.osmosdr_source.set_freq_corr(0)
            self.osmosdr_source.set_gain_mode(False, 0)
            self.osmosdr_source.set_gain(self.gain, 0)
            self.osmosdr_source.set_if_gain(20, 0)
            self.osmosdr_source.set_bb_gain(20, 0)
            
            # FFT processing - Updated for GNU Radio 3.10+
            self.stream_to_vector = blocks.stream_to_vector(gr.sizeof_gr_complex, 1024)
            
            # Try different FFT block locations for compatibility
            try:
                # GNU Radio 3.10+
                from gnuradio import fft
                self.fft_block = fft.fft_vcc(1024, True, [], False, 1)
            except ImportError:
                try:
                    # GNU Radio 3.9
                    self.fft_block = filter.fft_vcc(1024, True, [], False, 1)
                except AttributeError:
                    try:
                        # Alternative approach - use blocks.fft_vcc
                        self.fft_block = blocks.fft_vcc(1024, True, [], False, 1)
                    except AttributeError:
                        raise Exception("Cannot find compatible FFT block for this GNU Radio version")
            
            self.vector_sink = blocks.vector_sink_c(1024)
            
            # Connect blocks
            self.tb.connect(self.osmosdr_source, self.stream_to_vector)
            self.tb.connect(self.stream_to_vector, self.fft_block)
            self.tb.connect(self.fft_block, self.vector_sink)
            
            logger.info("HackRF flowgraph initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to setup HackRF: {e}")
            return False
    
    def start_acquisition(self):
        """Start RF data acquisition"""
        if not self.setup_flowgraph():
            return False
            
        try:
            self.tb.start()
            self.is_running = True
            logger.info(f"Started RF acquisition at {self.center_freq/1e6:.1f} MHz")
            return True
        except Exception as e:
            logger.error(f"Failed to start acquisition: {e}")
            return False
    
    def stop_acquisition(self):
        """Stop RF data acquisition"""
        if self.is_running and self.tb:
            try:
                self.tb.stop()
                self.tb.wait()
                self.is_running = False
                logger.info("Stopped RF acquisition")
            except Exception as e:
                logger.error(f"Error stopping acquisition: {e}")
    
    def get_fft_data(self) -> Optional[np.ndarray]:
        """Get latest FFT data from HackRF"""
        if not self.is_running or not self.vector_sink:
            return None
            
        try:
            data = self.vector_sink.data()
            if len(data) >= 1024:
                # Get most recent FFT frame
                latest_fft = np.array(data[-1024:])
                self.vector_sink.reset()  # Clear buffer
                return latest_fft
        except Exception as e:
            logger.error(f"Error getting FFT data: {e}")
        
        return None
    
    def set_frequency(self, freq: float):
        """Change center frequency"""
        if self.is_running and self.osmosdr_source:
            try:
                self.osmosdr_source.set_center_freq(freq)
                self.center_freq = freq
                logger.debug(f"Changed frequency to {freq/1e6:.1f} MHz")
            except Exception as e:
                logger.error(f"Error setting frequency: {e}")

class RFScannerDetector:
    """Main RF scanner detection system"""
    
    def __init__(self, config_file='rf_config.json'):
        self.config = self._load_config(config_file)
        self.hackrf = HackRFController(
            sample_rate=self.config.get('sample_rate', 2e6),
            gain=self.config.get('gain', 20)
        )
        self.analyzer = RFSpectrumAnalyzer(
            sample_rate=self.config.get('sample_rate', 2e6)
        )
        
        # Frequency sweeping parameters
        self.sweep_frequencies = self._generate_sweep_plan()
        self.current_freq_idx = 0
        self.sweep_dwell_time = self.config.get('sweep_dwell_time', 0.5)  # seconds
        
        # Detection storage
        self.detections = []
        self.detection_db = 'rf_detections.db'
        self._init_database()
        
        # Control flags
        self.is_running = False
        self.detection_thread = None

    def _load_config(self, config_file: str) -> Dict:
        """Load configuration from JSON file"""
        default_config = {
            'sample_rate': 2e6,
            'gain': 20,
            'frequency_ranges': [
                # VHF Low Band (Public Safety, Marine, Aviation)
                [30e6, 50e6],
                
                # VHF High Band (Public Safety, Business, Marine)
                [138e6, 174e6],
                
                # UHF Band (Public Safety, Business, GMRS/FRS)
                [420e6, 470e6],
                
                # 700 MHz Public Safety Band
                [763e6, 775e6],   # Narrowband
                [793e6, 805e6],   # Narrowband
                
                # 800 MHz Trunked Systems
                [806e6, 824e6],   # Public Safety
                [851e6, 869e6],   # Public Safety
                
                # 900 MHz ISM Band (Industrial, Scientific, Medical)
                [902e6, 928e6],
                
                # Additional Business/Industrial Bands
                [450e6, 470e6],   # UHF Business
                [470e6, 512e6],   # UHF T-Band (varies by region)
                
                # Aircraft Band (if monitoring aviation)
                [118e6, 137e6],   # VHF Aviation
                
                # Marine VHF
                [156e6, 162e6],   # Marine VHF
                
                # Amateur Radio Bands (potential scanner targets)
                [144e6, 148e6],   # VHF Amateur
                [420e6, 450e6],   # UHF Amateur
                
                # MURS (Multi-Use Radio Service)
                [151e6, 154e6],
                
                # Paging/Data
                [929e6, 932e6],   # Paging
                
                # Remote Control Frequencies
                [26e6, 27e6],     # CB Radio
                [49e6, 50e6],     # Remote Control
                [72e6, 76e6],     # Remote Control
                [315e6, 316e6],   # ISM Remote Control
                [433e6, 434e6],   # ISM Remote Control
            ],
            'sweep_step': 25e3,  # 25 kHz steps for better resolution
            'sweep_dwell_time': 0.5,
            'detection_thresholds': {
                'signal_threshold': -70,
                'min_hop_rate': 8,  # Increased from 5 to reduce false positives
                'max_dwell_time': 2.0,
                'active_probe_threshold': -20,  # Increased from -40 to be more selective
                'confidence_threshold': 0.7,
                'max_detections_per_cycle': 5  # Limit detections per analysis cycle
            },
            'system_settings': {
                'log_level': 'INFO',
                'database_retention_days': 30,
                'alert_cooldown_seconds': 60,
                'max_detections_per_minute': 10
            },
            'frequency_labels': {
                'VHF_LOW': [30e6, 50e6],
                'VHF_HIGH': [138e6, 174e6], 
                'UHF_BUSINESS': [420e6, 470e6],
                'UHF_PUBLIC_SAFETY': [450e6, 470e6],
                'GMRS_FRS': [462e6, 467e6],
                'ISM_900': [902e6, 928e6],
                'AVIATION': [118e6, 137e6],
                'MARINE': [156e6, 162e6],
                'PUBLIC_SAFETY_700': [763e6, 805e6],
                'PUBLIC_SAFETY_800': [806e6, 869e6],
                'AMATEUR_VHF': [144e6, 148e6],
                'AMATEUR_UHF': [420e6, 450e6],
                'MURS': [151e6, 154e6],
                'PAGING': [929e6, 932e6],
                'REMOTE_CONTROL': [315e6, 316e6, 433e6, 434e6]
            }
        }
        
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                # Merge with defaults, allowing user config to override
                for key, value in config.items():
                    default_config[key] = value
                logger.info(f"Loaded configuration from {config_file}")
        except FileNotFoundError:
            logger.info(f"Config file {config_file} not found, creating default configuration")
            
            # Create default config file with comments
            config_with_comments = {
                "_comment_sample_rate": "Sample rate in Hz (2 MHz recommended)",
                "sample_rate": default_config['sample_rate'],
                
                "_comment_gain": "RF gain setting (0-40 dB, start with 20)",
                "gain": default_config['gain'],
                
                "_comment_frequency_ranges": "Frequency ranges to monitor [start_hz, end_hz]",
                "frequency_ranges": default_config['frequency_ranges'],
                
                "_comment_sweep_step": "Frequency step size in Hz (25 kHz recommended)",
                "sweep_step": default_config['sweep_step'],
                
                "_comment_sweep_dwell_time": "Time to spend on each frequency in seconds",
                "sweep_dwell_time": default_config['sweep_dwell_time'],
                
                "_comment_detection_thresholds": "Thresholds for various detection algorithms",
                "detection_thresholds": default_config['detection_thresholds'],
                
                "_comment_system_settings": "General system configuration",
                "system_settings": default_config['system_settings'],
                
                "_comment_frequency_labels": "Human-readable labels for frequency ranges",
                "frequency_labels": default_config['frequency_labels'],
                
                "_usage_note": "Edit frequency_ranges to focus on specific bands of interest",
                "_legal_note": "Ensure compliance with local RF monitoring regulations"
            }
            
            # Save comprehensive default config
            try:
                with open(config_file, 'w') as f:
                    json.dump(config_with_comments, f, indent=2)
                logger.info(f"Created default configuration file: {config_file}")
            except Exception as e:
                logger.error(f"Failed to create config file: {e}")
        
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in config file {config_file}: {e}")
            logger.info("Using default configuration")
        except Exception as e:
            logger.error(f"Error loading config file {config_file}: {e}")
            logger.info("Using default configuration")
        
        # Validate frequency ranges
        validated_ranges = []
        for freq_range in default_config['frequency_ranges']:
            if len(freq_range) == 2 and freq_range[0] < freq_range[1]:
                # Ensure frequency range is within HackRF capabilities (1 MHz - 6 GHz)
                start_freq = max(freq_range[0], 1e6)
                end_freq = min(freq_range[1], 6e9)
                if start_freq < end_freq:
                    validated_ranges.append([start_freq, end_freq])
            else:
                logger.warning(f"Invalid frequency range: {freq_range}")
        
        default_config['frequency_ranges'] = validated_ranges
        
        # Log configuration summary
        total_bandwidth = sum(r[1] - r[0] for r in validated_ranges) / 1e6
        logger.info(f"Configuration loaded: {len(validated_ranges)} frequency ranges, {total_bandwidth:.1f} MHz total bandwidth")
        
        return default_config

    def _make_json_serializable(self, obj):
        """Convert NumPy types and other non-serializable objects to JSON-compatible types"""
        
        if isinstance(obj, dict):
            return {key: self._make_json_serializable(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._make_json_serializable(item) for item in obj]
        elif isinstance(obj, tuple):
            return tuple(self._make_json_serializable(item) for item in obj)
        elif isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, (np.bool_, bool)):
            return bool(obj)
        elif isinstance(obj, datetime):
            return obj.isoformat()
        elif obj is None or isinstance(obj, (str, int, float)):
            return obj
        else:
            # For any other types, convert to string as fallback
            return str(obj)

    def _classify_scanner_hardware(self, fingerprint: Dict) -> str:
        """Classify scanner hardware based on fingerprint"""
        
        adc_bits = fingerprint.get('estimated_adc_bits', 0)
        clock_precision = fingerprint.get('clock_precision_ppm', 1000)
        phase_noise = fingerprint.get('lo_phase_noise_db', 0)
        
        if adc_bits >= 14 and clock_precision <= 10 and phase_noise < -120:
            return "Professional SDR (High-End)"
        elif adc_bits >= 12 and clock_precision <= 100:
            return "Commercial Scanner (Mid-Range)"
        elif adc_bits >= 10 and clock_precision <= 1000:
            return "Consumer Scanner (Entry-Level)"
        else:
            return "Unknown/Custom Hardware"
    
    def _assess_persistence_level(self, device_tracking: Dict) -> str:
        """Assess how persistent this device has been"""
        
        detection_count = device_tracking.get('detection_count', 0)
        first_seen = device_tracking.get('first_seen')
        last_seen = device_tracking.get('last_seen')
        
        if first_seen and last_seen:
            time_span = (last_seen - first_seen).total_seconds()
            if time_span > 3600 and detection_count > 20:  # Active for >1 hour with many detections
                return "HIGH (Sustained Surveillance)"
            elif time_span > 1800 and detection_count > 10:  # Active for >30 min
                return "MEDIUM (Extended Monitoring)"
            elif detection_count > 5:
                return "LOW (Brief Activity)"
        
        return "MINIMAL (Single Detection)"
    
    def _identify_scanner_hardware_type(self, fingerprint: Dict) -> str:
        """Identify specific scanner hardware type"""
        
        scan_algorithm = fingerprint.get('scan_algorithm', '')
        hop_rate_stability = fingerprint.get('hop_rate_stability', 1.0)
        
        if 'fast_digital_scan' in scan_algorithm and hop_rate_stability < 0.1:
            return "Digital Trunking Scanner (Professional)"
        elif 'parallel_scan' in scan_algorithm:
            return "Multi-Channel Scanner or SDR"
        elif hop_rate_stability > 0.5:
            return "Analog Scanner (Consumer Grade)"
        else:
            return "Standard Digital Scanner"
    
    def _classify_monitoring_equipment(self, fingerprint: Dict) -> str:
        """Classify monitoring equipment based on fingerprint"""
        
        stability = fingerprint.get('monitoring_consistency', 'unknown')
        phase_noise = fingerprint.get('lo_phase_noise_db', 0)
        
        if phase_noise < -130:
            return "Surveillance Receiver (Professional)"
        elif phase_noise < -110:
            return "Communications Receiver (Commercial)"
        else:
            return "Scanner in Monitor Mode"
    
    def _assess_df_capability(self, fingerprint: Dict) -> str:
        """Assess direction finding capability"""
        
        probe_power = fingerprint.get('probe_power', -100)
        burst_duration = fingerprint.get('burst_duration', 0)
        
        if probe_power > 10 and burst_duration < 0.1:
            return "Likely DF Equipment"
        elif probe_power > 0:
            return "Possible DF Capability"
        else:
            return "Passive Monitoring Only"
    
    def _assess_enhanced_threat_level(self, detection: RFDetection, fingerprint: Dict, tracking: Dict) -> Dict:
        """Enhanced threat assessment using device fingerprint and history"""
        
        base_score = detection.confidence * 3  # Start with detection confidence
        
        # Hardware sophistication factor
        adc_bits = fingerprint.get('estimated_adc_bits', 8)
        if adc_bits >= 14:
            base_score += 3  # Professional equipment
        elif adc_bits >= 12:
            base_score += 2  # Commercial equipment
        
        # Persistence factor
        if tracking:
            detection_count = tracking.get('detection_count', 1)
            if detection_count > 20:
                base_score += 3  # Very persistent
            elif detection_count > 10:
                base_score += 2  # Moderately persistent
            elif detection_count > 5:
                base_score += 1  # Somewhat persistent
        
        # Capability assessment
        capability_indicators = 0
        if fingerprint.get('clock_precision_ppm', 1000) < 10:
            capability_indicators += 1  # High precision timing
        if fingerprint.get('lo_phase_noise_db', 0) < -120:
            capability_indicators += 1  # Low phase noise
        if fingerprint.get('scan_efficiency', 0) > 0.8:
            capability_indicators += 1  # Efficient scanning
        
        base_score += capability_indicators
        
        # Cap at 10
        final_score = min(base_score, 10)
        
        # Determine categories
        if final_score >= 8:
            level = "CRITICAL"
            device_category = "Professional Surveillance Equipment"
            capability_level = "Advanced"
            recommendation = "Immediate operational security review required"
            intelligence_value = "High - Advanced threat actor"
        elif final_score >= 6:
            level = "HIGH"
            device_category = "Commercial Reconnaissance Equipment"
            capability_level = "Intermediate"
            recommendation = "Enhanced security measures recommended"
            intelligence_value = "Medium - Organized surveillance"
        elif final_score >= 4:
            level = "MEDIUM"
            device_category = "Standard Scanner Equipment"
            capability_level = "Basic"
            recommendation = "Monitor and assess patterns"
            intelligence_value = "Low - Routine scanning activity"
        else:
            level = "LOW"
            device_category = "Consumer Equipment"
            capability_level = "Minimal"
            recommendation = "Normal monitoring sufficient"
            intelligence_value = "Minimal - Hobbyist activity"
        
        persistence_factor = min(tracking.get('detection_count', 1) / 10.0, 1.0) if tracking else 0.1
        
        return {
            'score': final_score,
            'level': level,
            'device_category': device_category,
            'persistence_factor': persistence_factor,
            'capability_level': capability_level,
            'recommendation': recommendation,
            'intelligence_value': intelligence_value
        }
    
    def _assess_fingerprint_stability(self, tracking: Dict) -> str:
        """Assess how stable the device fingerprint is"""
        
        fingerprints = tracking.get('fingerprint_evolution', [])
        if len(fingerprints) < 2:
            return "Insufficient data"
        
        # Compare key characteristics across fingerprints
        stability_factors = []
        for i in range(1, len(fingerprints)):
            fp1 = fingerprints[i-1]['fingerprint']
            fp2 = fingerprints[i]['fingerprint']
            
            # Compare DC offset stability
            dc1 = fp1.get('dc_offset', 0)
            dc2 = fp2.get('dc_offset', 0)
            if abs(dc1 - dc2) < 1.0:  # Within 1 dB
                stability_factors.append(1)
            else:
                stability_factors.append(0)
        
        stability_ratio = sum(stability_factors) / len(stability_factors)
        
        if stability_ratio > 0.8:
            return "Very Stable (Same Hardware)"
        elif stability_ratio > 0.6:
            return "Stable (Consistent Equipment)"
        elif stability_ratio > 0.4:
            return "Moderate (Some Variation)"
        else:
            return "Unstable (Multiple Devices or Interference)"
    
    def _store_enhanced_detection_with_tracking(self, detection: RFDetection, fingerprint: Dict, tracking: Dict):
        """Store detection with enhanced fingerprint and tracking data"""
        
        enhanced_metadata = detection.metadata.copy()
        enhanced_metadata.update({
            'enhanced_fingerprint': fingerprint,
            'device_tracking_summary': {
                'device_id': fingerprint.get('device_id'),
                'detection_count': tracking.get('detection_count', 1) if tracking else 1,
                'persistence_level': self._assess_persistence_level(tracking) if tracking else "NEW",
                'threat_assessment': self._assess_enhanced_threat_level(detection, fingerprint, tracking)
            },
            'analysis_timestamp': datetime.now().isoformat()
        })
        
        # Convert to JSON-serializable format
        serializable_metadata = self._make_json_serializable(enhanced_metadata)
        
        # Store in database with enhanced metadata
        try:
            conn = sqlite3.connect(self.detection_db)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO detections 
                (timestamp, frequency, signal_strength, detection_type, confidence, duration, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                detection.timestamp.isoformat(),
                detection.frequency,
                detection.signal_strength,
                f"{detection.detection_type}_enhanced",
                detection.confidence,
                detection.duration,
                json.dumps(serializable_metadata)
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to store enhanced detection: {e}")

    def _confidence_description(self, confidence: float) -> str:
        """Convert confidence score to human-readable description"""
        if confidence >= 0.9:
            return "VERY HIGH"
        elif confidence >= 0.8:
            return "HIGH"
        elif confidence >= 0.7:
            return "MEDIUM-HIGH"
        elif confidence >= 0.6:
            return "MEDIUM"
        elif confidence >= 0.5:
            return "MEDIUM-LOW"
        else:
            return "LOW"
    
    def _assess_persistence_level(self, device_tracking: Dict) -> str:
        """Assess how persistent this device has been"""
        
        detection_count = device_tracking.get('detection_count', 0)
        first_seen = device_tracking.get('first_seen')
        last_seen = device_tracking.get('last_seen')
        
        if first_seen and last_seen:
            time_span = (last_seen - first_seen).total_seconds()
            if time_span > 3600 and detection_count > 20:  # Active for >1 hour with many detections
                return "HIGH (Sustained Surveillance)"
            elif time_span > 1800 and detection_count > 10:  # Active for >30 min
                return "MEDIUM (Extended Monitoring)"
            elif detection_count > 5:
                return "LOW (Brief Activity)"
        
        return "MINIMAL (Single Detection)"

    def _generate_sweep_plan(self) -> List[float]:
        """Generate frequency sweep plan based on config"""
        frequencies = []
        
        for freq_range in self.config['frequency_ranges']:
            start_freq, end_freq = freq_range
            step = self.config.get('sweep_step', 1e6)
            
            current_freq = start_freq
            while current_freq <= end_freq:
                frequencies.append(current_freq)
                current_freq += step
        
        logger.info(f"Generated sweep plan with {len(frequencies)} frequencies")
        return frequencies
    
    def _init_database(self):
        """Initialize SQLite database for detections"""
        conn = sqlite3.connect(self.detection_db)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                frequency REAL,
                signal_strength REAL,
                detection_type TEXT,
                confidence REAL,
                duration REAL,
                metadata TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _save_detection(self, detection: RFDetection):
        """Save detection to database"""
        conn = sqlite3.connect(self.detection_db)
        cursor = conn.cursor()
        
        # Convert metadata to JSON-serializable format
        serializable_metadata = self._make_json_serializable(detection.metadata)
        
        cursor.execute('''
            INSERT INTO detections 
            (timestamp, frequency, signal_strength, detection_type, confidence, duration, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            detection.timestamp.isoformat(),
            detection.frequency,
            detection.signal_strength,
            detection.detection_type,
            detection.confidence,
            detection.duration,
            json.dumps(serializable_metadata)
        ))
        
        conn.commit()
        conn.close()

    def _detection_loop(self):
        """Main detection loop running in separate thread"""
        logger.info("Starting RF scanner detection loop")
        
        while self.is_running:
            # Frequency sweep
            current_freq = self.sweep_frequencies[self.current_freq_idx]
            self.hackrf.set_frequency(current_freq)
            
            # Dwell on frequency
            time.sleep(self.sweep_dwell_time)
            
            # Get and analyze data
            fft_data = self.hackrf.get_fft_data()
            if fft_data is not None:
                detections = self.analyzer.analyze_spectrum(fft_data, current_freq)
                
                # Rate limiting - only process up to max_detections_per_cycle
                max_detections = self.config.get('detection_thresholds', {}).get('max_detections_per_cycle', 5)
                if len(detections) > max_detections:
                    # Keep only highest confidence detections
                    detections = sorted(detections, key=lambda d: d.confidence, reverse=True)[:max_detections]
                
                # Process detections
                for detection in detections:
                    self.detections.append(detection)
                    self._save_detection(detection)
                    self._alert_on_detection(detection)
            
            # Move to next frequency
            self.current_freq_idx = (self.current_freq_idx + 1) % len(self.sweep_frequencies)
            
            # Brief pause between frequencies
            time.sleep(0.1)

    def _alert_on_detection(self, detection: RFDetection):
        """Handle detection alerts with enhanced fingerprinting"""
        
        # Get enhanced fingerprint if available in detection metadata
        enhanced_fingerprint = detection.metadata.get('enhanced_fingerprint', {})
        device_id = enhanced_fingerprint.get('device_id', 'Unknown')
        
        # Get device tracking information (with safety check)
        if hasattr(self.analyzer, 'device_tracking'):
            device_tracking = self.analyzer.device_tracking.get(device_id, {})
        else:
            self.analyzer.device_tracking = {}  # Initialize if missing
            device_tracking = {}
        
        # Build comprehensive alert message
        alert_msg = f"""
        ═══════════════════════════════════════════════════════════════
        RF SCANNER DETECTION ALERT
        ═══════════════════════════════════════════════════════════════
        
        BASIC DETECTION INFO:
        ├─ Detection Type: {detection.detection_type.upper()}
        ├─ Timestamp: {detection.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
        ├─ Frequency: {detection.frequency/1e6:.6f} MHz
        ├─ Signal Strength: {detection.signal_strength:.1f} dBm
        ├─ Confidence Score: {detection.confidence:.3f} ({self._confidence_description(detection.confidence)})
        └─ Duration: {detection.duration:.2f} seconds"""
        
        # Only add enhanced sections if fingerprint data is available
        if enhanced_fingerprint:
            alert_msg += f"""
        
        DEVICE FINGERPRINT:
        ├─ Device ID: {device_id}
        ├─ Hardware Signature: {enhanced_fingerprint.get('dc_offset', 'N/A')} dBm DC offset
        ├─ Estimated ADC Bits: {enhanced_fingerprint.get('estimated_adc_bits', 'Unknown')}
        ├─ Clock Precision: {enhanced_fingerprint.get('clock_precision_ppm', 'Unknown')} PPM
        ├─ Frequency Response: {enhanced_fingerprint.get('frequency_response_flatness', 'Unknown')} dB variation
        └─ Scanner Classification: {enhanced_fingerprint.get('scanner_classification', 'Unknown')}"""
            
            # Device tracking section
            if device_tracking:
                time_since_first = detection.timestamp - device_tracking['first_seen']
                alert_msg += f"""
        
        DEVICE TRACKING:
        ├─ First Seen: {device_tracking['first_seen'].strftime('%Y-%m-%d %H:%M:%S')}
        ├─ Time Active: {str(time_since_first).split('.')[0]}
        ├─ Total Detections: {device_tracking['detection_count']}
        ├─ Primary Behavior: {device_tracking.get('primary_behavior', 'unknown')}
        └─ Persistence Level: {self._assess_persistence_level(device_tracking)}"""
            else:
                alert_msg += """
        
        DEVICE TRACKING:
        └─ Status: NEW DEVICE - First Detection"""
        
        # Basic pattern analysis (always show)
        alert_msg += f"""
        
        PATTERN ANALYSIS:"""
        
        if detection.detection_type == 'scanning':
            metadata = detection.metadata
            freq_range = metadata.get('frequency_range', (0, 0))
            alert_msg += f"""
        ├─ Hop Rate: {metadata.get('hop_rate', 0):.1f} channels/second
        ├─ Frequencies Detected: {metadata.get('frequencies_detected', 0)}
        ├─ Frequency Range: {freq_range[0]/1e6:.3f} - {freq_range[1]/1e6:.3f} MHz
        └─ Channel Spacing: {metadata.get('channel_spacing', 0)/1e3:.1f} kHz"""
        
        elif detection.detection_type == 'targeted':
            metadata = detection.metadata
            alert_msg += f"""
        ├─ Dwell Time: {metadata.get('dwell_time', 0):.1f} seconds
        ├─ Power Variance: {metadata.get('power_variance', 0):.2f} dB²
        └─ Sample Count: {metadata.get('sample_count', 0)}"""
        
        elif detection.detection_type == 'active_probe':
            metadata = detection.metadata
            alert_msg += f"""
        ├─ Probe Power: {metadata.get('probe_power', 0):.1f} dBm
        ├─ Above Threshold: {metadata.get('above_threshold', 0):.1f} dB
        └─ Burst Duration: {detection.duration * 1000:.1f} ms"""
        
        # Basic threat assessment
        confidence_level = self._confidence_description(detection.confidence)
        if detection.confidence > 0.8:
            threat_level = "HIGH"
            recommendation = "Monitor closely and consider countermeasures"
        elif detection.confidence > 0.6:
            threat_level = "MEDIUM"
            recommendation = "Continue monitoring"
        else:
            threat_level = "LOW"
            recommendation = "Log for analysis"
        
        alert_msg += f"""
        
        THREAT ASSESSMENT:
        ├─ Threat Level: {threat_level}
        ├─ Confidence: {confidence_level}
        └─ Recommendation: {recommendation}
        
        ═══════════════════════════════════════════════════════════════
        """
        
        logger.warning(alert_msg)
        
        # Store enhanced detection data
        self._save_detection(detection)
    
    def start_detection(self):
        """Start the RF scanner detection system"""
        if self.is_running:
            logger.warning("Detection system already running")
            return False
        
        if not self.hackrf.start_acquisition():
            logger.error("Failed to start HackRF acquisition")
            return False
        
        self.is_running = True
        self.detection_thread = threading.Thread(target=self._detection_loop)
        self.detection_thread.daemon = True
        self.detection_thread.start()
        
        logger.info("RF Scanner Detection System started successfully")
        return True
    
    def stop_detection(self):
        """Stop the RF scanner detection system"""
        if not self.is_running:
            return
        
        self.is_running = False
        self.hackrf.stop_acquisition()
        
        if self.detection_thread:
            self.detection_thread.join(timeout=5)
        
        logger.info("RF Scanner Detection System stopped")
    
    def get_recent_detections(self, hours=24) -> List[RFDetection]:
        """Get recent detections from database"""
        conn = sqlite3.connect(self.detection_db)
        cursor = conn.cursor()
        
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        cursor.execute('''
            SELECT * FROM detections 
            WHERE timestamp > ? 
            ORDER BY timestamp DESC
        ''', (cutoff_time.isoformat(),))
        
        rows = cursor.fetchall()
        conn.close()
        
        detections = []
        for row in rows:
            detection = RFDetection(
                timestamp=datetime.fromisoformat(row[1]),
                frequency=row[2],
                signal_strength=row[3],
                detection_type=row[4],
                confidence=row[5],
                duration=row[6],
                metadata=json.loads(row[7])
            )
            detections.append(detection)
        
        return detections

    def _generate_signal_fingerprint(self, detection: RFDetection) -> Dict:
        """Generate detailed signal fingerprint from detection"""
        
        # Get the most recent FFT data for analysis
        fft_data = self.hackrf.get_fft_data()
        if fft_data is None:
            return {'error': 'No FFT data available'}
        
        fingerprint = {}
        
        try:
            # Basic signal analysis
            power_spectrum = 20 * np.log10(np.abs(fft_data) + 1e-12)
            
            # Calculate noise floor and SNR
            noise_floor = np.percentile(power_spectrum, 10)
            peak_power = np.max(power_spectrum)
            fingerprint['snr'] = peak_power - noise_floor
            fingerprint['noise_floor'] = noise_floor
            
            # Find peak frequency
            peak_idx = np.argmax(power_spectrum)
            freqs = np.fft.fftfreq(len(fft_data), 1/self.analyzer.sample_rate) + self.hackrf.center_freq
            fingerprint['peak_frequency'] = freqs[peak_idx]
            fingerprint['center_frequency'] = self.hackrf.center_freq
            fingerprint['frequency_offset'] = freqs[peak_idx] - self.hackrf.center_freq
            
            # Calculate bandwidth (-3dB bandwidth)
            half_max = peak_power - 3
            above_half_max = np.where(power_spectrum > half_max)[0]
            if len(above_half_max) > 1:
                bandwidth_bins = above_half_max[-1] - above_half_max[0]
                fingerprint['bandwidth'] = bandwidth_bins * (self.analyzer.sample_rate / len(fft_data))
            else:
                fingerprint['bandwidth'] = 0
            
            # Spectral analysis
            spectral_power = np.sum(power_spectrum[power_spectrum > noise_floor + 6])
            total_power = np.sum(power_spectrum)
            fingerprint['spectral_purity'] = (spectral_power / total_power) * 100 if total_power > 0 else 0
            
            # Phase noise analysis (simplified)
            if len(fft_data) > 100:
                phase = np.angle(fft_data)
                phase_diff = np.diff(np.unwrap(phase))
                fingerprint['phase_noise'] = np.var(phase_diff)
            else:
                fingerprint['phase_noise'] = 0
            
            # Signal characteristics
            fingerprint['rise_time'] = self._estimate_rise_time(fft_data)
            fingerprint['modulation_type'] = self._classify_modulation(fft_data, power_spectrum)
            fingerprint['stability_rating'] = self._assess_signal_stability(detection.frequency)
            
            # Equipment classification
            fingerprint['equipment_signature'] = self._classify_equipment_signature(fingerprint)
            fingerprint['scanner_classification'] = self._classify_scanner_type(detection, fingerprint)
            
            # Pattern analysis for scanning detection
            if detection.detection_type == 'scanning':
                fingerprint['monitoring_pattern'] = self._analyze_scanning_pattern(detection)
            elif detection.detection_type == 'targeted':
                fingerprint['monitoring_pattern'] = 'Targeted Monitoring'
            elif detection.detection_type == 'active_probe':
                fingerprint['probe_type'] = self._classify_probe_type(fingerprint)
            
            # Timing analysis
            fingerprint['detection_latency'] = (datetime.now() - detection.timestamp).total_seconds() * 1000
            fingerprint['signal_onset'] = self._estimate_signal_onset(detection.frequency)
            fingerprint['previous_activity'] = self._check_previous_activity(detection.frequency)
            
        except Exception as e:
            logger.error(f"Error generating signal fingerprint: {e}")
            fingerprint['error'] = str(e)
        
        return fingerprint
    
    def _confidence_description(self, confidence: float) -> str:
        """Convert confidence score to human-readable description"""
        if confidence >= 0.9:
            return "VERY HIGH"
        elif confidence >= 0.8:
            return "HIGH"
        elif confidence >= 0.7:
            return "MEDIUM-HIGH"
        elif confidence >= 0.6:
            return "MEDIUM"
        elif confidence >= 0.5:
            return "MEDIUM-LOW"
        else:
            return "LOW"
    
    def _estimate_rise_time(self, fft_data: np.ndarray) -> float:
        """Estimate signal rise time from FFT data"""
        try:
            envelope = np.abs(fft_data)
            if len(envelope) > 10:
                # Find rise from 10% to 90% of peak
                peak_val = np.max(envelope)
                rise_10 = np.where(envelope > 0.1 * peak_val)[0]
                rise_90 = np.where(envelope > 0.9 * peak_val)[0]
                
                if len(rise_10) > 0 and len(rise_90) > 0:
                    rise_samples = rise_90[0] - rise_10[0]
                    return (rise_samples / self.analyzer.sample_rate) * 1000  # Convert to ms
            return 0.0
        except:
            return 0.0
    
    def _classify_modulation(self, fft_data: np.ndarray, power_spectrum: np.ndarray) -> str:
        """Classify the modulation type based on signal characteristics"""
        
        # Simple modulation classification based on spectral shape
        peak_power = np.max(power_spectrum)
        noise_floor = np.percentile(power_spectrum, 10)
        
        # Count significant spectral peaks
        peaks = np.where(power_spectrum > noise_floor + 10)[0]
        
        if len(peaks) == 0:
            return "No Signal"
        elif len(peaks) == 1:
            return "CW/Narrow FM"
        elif len(peaks) < 5:
            return "FM/Digital"
        elif len(peaks) < 20:
            return "Wideband FM/Digital"
        else:
            return "Spread Spectrum/Noise"
    
    def _assess_signal_stability(self, frequency: float) -> str:
        """Assess signal stability based on historical data"""
        
        if frequency not in self.analyzer.frequency_history:
            return "New Signal"
        
        history = list(self.analyzer.frequency_history[frequency])
        if len(history) < 3:
            return "Insufficient Data"
        
        powers = [power for _, power in history[-10:]]  # Last 10 measurements
        power_variance = np.var(powers)
        
        if power_variance < 1.0:
            return "Very Stable"
        elif power_variance < 5.0:
            return "Stable"
        elif power_variance < 15.0:
            return "Moderately Stable"
        else:
            return "Unstable"
    
    def _classify_equipment_signature(self, fingerprint: Dict) -> str:
        """Classify equipment type based on signal fingerprint"""
        
        phase_noise = fingerprint.get('phase_noise', 0)
        rise_time = fingerprint.get('rise_time', 0)
        bandwidth = fingerprint.get('bandwidth', 0)
        
        if phase_noise > 0.1 and rise_time < 0.1:
            return "Professional SDR Equipment"
        elif phase_noise < 0.01 and rise_time > 1.0:
            return "Crystal-Controlled Scanner"
        elif bandwidth > 100e3:
            return "Wideband Scanner/Analyzer"
        elif rise_time < 0.5:
            return "Fast-Switching Scanner"
        else:
            return "Unknown Equipment Type"
    
    def _classify_scanner_type(self, detection: RFDetection, fingerprint: Dict) -> str:
        """Classify scanner type based on detection and fingerprint"""
        
        if detection.detection_type == 'scanning':
            hop_rate = detection.metadata.get('hop_rate', 0)
            channel_spacing = detection.metadata.get('channel_spacing', 0)
            
            if hop_rate > 100:
                return "High-Speed Digital Scanner"
            elif hop_rate > 20:
                return "Fast Analog Scanner"
            elif channel_spacing == 25e3:
                return "Standard Scanner (25kHz steps)"
            elif channel_spacing == 12.5e3:
                return "Narrowband Scanner (12.5kHz steps)"
            else:
                return "Custom/SDR Scanner"
        
        elif detection.detection_type == 'targeted':
            dwell_time = detection.metadata.get('dwell_time', 0)
            if dwell_time > 300:  # 5 minutes
                return "Surveillance Receiver"
            elif dwell_time > 60:   # 1 minute
                return "Monitoring Scanner"
            else:
                return "Brief Monitor"
        
        elif detection.detection_type == 'active_probe':
            probe_power = detection.metadata.get('probe_power', -100)
            if probe_power > 10:
                return "High-Power Probe/Jammer"
            elif probe_power > -10:
                return "Direction Finding Equipment"
            else:
                return "Low-Power Probe"
        
        return "Unknown Scanner Type"
    
    def _analyze_scanning_pattern(self, detection: RFDetection) -> str:
        """Analyze the specific scanning pattern"""
        
        metadata = detection.metadata
        hop_rate = metadata.get('hop_rate', 0)
        freq_range = metadata.get('frequency_range', (0, 0))
        freq_span = (freq_range[1] - freq_range[0]) / 1e6  # MHz
        
        if hop_rate > 50:
            return f"Rapid Scan ({hop_rate:.1f} ch/s over {freq_span:.1f} MHz)"
        elif hop_rate > 10:
            return f"Medium Scan ({hop_rate:.1f} ch/s over {freq_span:.1f} MHz)"
        else:
            return f"Slow Scan ({hop_rate:.1f} ch/s over {freq_span:.1f} MHz)"
    
    def _classify_probe_type(self, fingerprint: Dict) -> str:
        """Classify the type of active probe"""
        
        bandwidth = fingerprint.get('bandwidth', 0)
        rise_time = fingerprint.get('rise_time', 0)
        
        if bandwidth > 1e6:  # > 1 MHz bandwidth
            return "Wideband Probe/Jammer"
        elif rise_time < 0.1:  # < 0.1 ms rise time
            return "Fast Direction Finding Probe"
        elif bandwidth < 25e3:  # < 25 kHz bandwidth
            return "Narrowband Test Signal"
        else:
            return "Standard RF Probe"
    
    def _estimate_signal_onset(self, frequency: float) -> str:
        """Estimate when signal first appeared"""
        
        if frequency not in self.analyzer.frequency_history:
            return "Just Detected"
        
        history = list(self.analyzer.frequency_history[frequency])
        if len(history) == 0:
            return "Just Detected"
        
        first_detection = history[0][0]
        time_since_first = (datetime.now() - first_detection).total_seconds()
        
        if time_since_first < 5:
            return f"First seen {time_since_first:.1f}s ago"
        elif time_since_first < 60:
            return f"First seen {time_since_first:.0f}s ago"
        elif time_since_first < 3600:
            return f"First seen {time_since_first/60:.1f}m ago"
        else:
            return f"First seen {time_since_first/3600:.1f}h ago"
    
    def _check_previous_activity(self, frequency: float) -> str:
        """Check for previous activity on this frequency"""
        
        # Query database for historical activity
        try:
            conn = sqlite3.connect(self.detection_db)
            cursor = conn.cursor()
            
            # Look for detections on this frequency in the last 24 hours
            yesterday = datetime.now() - timedelta(hours=24)
            cursor.execute('''
                SELECT COUNT(*), MAX(timestamp), detection_type 
                FROM detections 
                WHERE frequency BETWEEN ? AND ? AND timestamp > ?
                GROUP BY detection_type
            ''', (frequency - 1000, frequency + 1000, yesterday.isoformat()))
            
            results = cursor.fetchall()
            conn.close()
            
            if not results:
                return "No previous activity"
            
            activity_summary = []
            for count, last_time, det_type in results:
                activity_summary.append(f"{count} {det_type} detections")
            
            return f"Last 24h: {', '.join(activity_summary)}"
            
        except Exception as e:
            return f"History check failed: {e}"
    
    def _assess_threat_level(self, detection: RFDetection, fingerprint: Dict) -> Dict:
        """Comprehensive threat level assessment"""
        
        base_score = detection.confidence * 5  # Start with confidence-based score
        
        # Adjust score based on detection type
        if detection.detection_type == 'scanning':
            hop_rate = detection.metadata.get('hop_rate', 0)
            if hop_rate > 100:
                base_score += 3  # Very fast scanning is more concerning
            elif hop_rate > 20:
                base_score += 2
            else:
                base_score += 1
        
        elif detection.detection_type == 'targeted':
            dwell_time = detection.metadata.get('dwell_time', 0)
            if dwell_time > 300:  # 5+ minutes of monitoring
                base_score += 4
            elif dwell_time > 60:  # 1+ minute
                base_score += 2
            else:
                base_score += 1
        
        elif detection.detection_type == 'active_probe':
            probe_power = detection.metadata.get('probe_power', -100)
            if probe_power > 10:
                base_score += 4  # High power probes are very concerning
            elif probe_power > 0:
                base_score += 3
            else:
                base_score += 2
        
        # Adjust for signal characteristics
        snr = fingerprint.get('snr', 0)
        if snr > 30:  # Very strong signal
            base_score += 1
        
        # Cap score at 10
        final_score = min(base_score, 10)
        
        # Determine threat level and recommendations
        if final_score >= 8:
            level = "CRITICAL"
            likelihood = "High probability of active surveillance"
            recommendation = "Immediate investigation required"
            followup = "Consider operational security measures"
        elif final_score >= 6:
            level = "HIGH"
            likelihood = "Likely surveillance activity"
            recommendation = "Investigate and monitor closely"
            followup = "Review communication security"
        elif final_score >= 4:
            level = "MEDIUM"
            likelihood = "Possible scanning activity"
            recommendation = "Continue monitoring"
            followup = "Document patterns for analysis"
        else:
            level = "LOW"
            likelihood = "May be routine scanner usage"
            recommendation = "Normal monitoring"
            followup = "Log for trend analysis"
        
        return {
            'score': final_score,
            'level': level,
            'likelihood': likelihood,
            'recommendation': recommendation,
            'followup': followup
        }
    
    def _store_enhanced_detection(self, detection: RFDetection, enhanced_data: Dict):
        """Store enhanced detection data in database"""
        
        # Update detection metadata with enhanced data
        enhanced_metadata = detection.metadata.copy()
        enhanced_metadata['fingerprint'] = enhanced_data
        enhanced_metadata['enhanced_analysis_timestamp'] = datetime.now().isoformat()
        
        # Update database record if it exists, or create new enhanced record
        try:
            conn = sqlite3.connect(self.detection_db)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO detections 
                (timestamp, frequency, signal_strength, detection_type, confidence, duration, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                detection.timestamp.isoformat(),
                detection.frequency,
                detection.signal_strength,
                f"{detection.detection_type}_enhanced",
                detection.confidence,
                detection.duration,
                json.dumps(enhanced_metadata)
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to store enhanced detection: {e}")

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

def check_for_updates():
    """Check if a newer version is available, force update if needed, and exit after update"""
    import os
    import sys
    import subprocess
    import requests
    
    base_dir = os.path.dirname(__file__)
    current_version_file = os.path.join(base_dir, 'version.txt')
    
    if not os.path.isfile(current_version_file):
        print("Version file not found.")
        return
    
    with open(current_version_file, 'r') as f:
        current_version = f.read().strip()
    
    try:
        response = requests.get("https://raw.githubusercontent.com/sec0ps/rf_surveillance/main/version.txt", timeout=5)
        if response.status_code == 200:
            latest_version = response.text.strip()
            if latest_version != current_version:
                print(f"Update available: {latest_version} (current: {current_version})")
                print("Pulling latest changes from GitHub...")
                try:
                    # Detect venv directory to preserve
                    venv_dirs = ['venv', '.venv', 'env']
                    exclude_dir = None
                    for d in venv_dirs:
                        full_path = os.path.join(base_dir, d)
                        if os.path.isdir(full_path):
                            exclude_dir = d
                            break
                    
                    # Perform update
                    subprocess.run(["git", "reset", "--hard"], check=True)
                    if exclude_dir:
                        subprocess.run(["git", "clean", "-fd", "-e", exclude_dir], check=True)
                    else:
                        subprocess.run(["git", "clean", "-fd"], check=True)
                    subprocess.run(["git", "pull"], check=True)
                    
                    # Update local version.txt
                    with open(current_version_file, 'w') as f:
                        f.write(latest_version + "\n")
                    
                    print("Update completed successfully.")
                    logger.info("RF Scanner Detection updated to version %s — exiting for updates to take effect.", latest_version)
                    sys.exit(0)
                    
                except subprocess.CalledProcessError as e:
                    print(f"Git update failed: {e}")
                    logger.error("Update failed: %s", str(e))
                    sys.exit(1)
            else:
                print("RF Scanner Detection is up to date.")
        else:
            print(f"Failed to check for updates (HTTP status {response.status_code}).")
    except Exception as e:
        print(f"Update check error: {e}")
        logger.warning("Update check failed: %s", str(e))

def main():
    """Main function for running the RF Scanner Detector"""
    import signal
    import sys
    
    # Check for updates on startup
    check_for_updates()
    
    detector = RFScannerDetector()
    
    def signal_handler(sig, frame):
        logger.info("Shutdown signal received")
        detector.stop_detection()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        if detector.start_detection():
            logger.info("RF Scanner Detection System is running. Press Ctrl+C to stop.")
            
            # Keep main thread alive and provide status updates
            while True:
                time.sleep(60)  # Status update every minute
                recent_detections = detector.get_recent_detections(hours=1)
                if recent_detections:
                    logger.info(f"Detections in last hour: {len(recent_detections)}")
                
        else:
            logger.error("Failed to start detection system")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        detector.stop_detection()
        sys.exit(1)

if __name__ == "__main__":
    main()
