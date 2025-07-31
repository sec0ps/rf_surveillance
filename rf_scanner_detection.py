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

try:
    from gnuradio import gr, blocks, analog, filter
    from gnuradio import uhd
    import osmosdr
except ImportError:
    print("GNU Radio not installed. Install with: pip install gnuradio")
    raise

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
    """Core RF spectrum analysis and pattern detection"""
    
    def __init__(self, sample_rate=2e6, fft_size=1024):
        self.sample_rate = sample_rate
        self.fft_size = fft_size
        self.frequency_history = defaultdict(deque)
        self.signal_threshold = -70  # dBm threshold for signal detection
        self.scan_detection_window = 30  # seconds
        
        # Pattern detection parameters
        self.min_hop_rate = 5  # hops per second to consider scanning
        self.max_dwell_time = 2.0  # seconds before considering targeted
        self.active_probe_threshold = -40  # dBm for active transmission detection
        
    def analyze_spectrum(self, fft_data: np.ndarray, center_freq: float) -> List[RFDetection]:
        """Analyze FFT data for scanning patterns"""
        detections = []
        current_time = datetime.now()
        
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
        
        if len(recent_freqs) > self.min_hop_rate * 5:  # 5-second window
            # Calculate hop rate
            hop_rate = len(recent_freqs) / 5.0
            avg_power = np.mean([power for _, _, power in recent_freqs])
            
            detection = RFDetection(
                timestamp=current_time,
                frequency=0,  # Multiple frequencies
                signal_strength=avg_power,
                detection_type='scanning',
                confidence=min(0.95, hop_rate / 20.0),  # Higher hop rate = higher confidence
                duration=5.0,
                metadata={
                    'hop_rate': hop_rate,
                    'frequencies_detected': len(recent_freqs),
                    'frequency_range': (min(recent_freqs, key=lambda x: x[0])[0],
                                      max(recent_freqs, key=lambda x: x[0])[0])
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
        
        for idx in strong_signals:
            freq = freqs[idx]
            power = power_spectrum[idx]
            
            # Check if this is a brief, strong signal (characteristic of active probes)
            detection = RFDetection(
                timestamp=current_time,
                frequency=freq,
                signal_strength=power,
                detection_type='active_probe',
                confidence=min(0.8, (power - self.active_probe_threshold) / 20.0),
                duration=0.1,  # Brief probe
                metadata={
                    'probe_power': power,
                    'above_threshold': power - self.active_probe_threshold
                }
            )
            detections.append(detection)
        
        return detections

class HackRFController:
    """HackRF device control and data acquisition"""
    
    def __init__(self, sample_rate=2e6, gain=20):
        self.sample_rate = sample_rate
        self.gain = gain
        self.center_freq = 400e6  # Starting frequency
        self.is_running = False
        self.data_queue = queue.Queue(maxsize=100)
        
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
            
            # FFT processing
            self.stream_to_vector = blocks.stream_to_vector(gr.sizeof_gr_complex, 1024)
            self.fft = filter.fft_vcc(1024, True, [], False, 1)
            self.vector_sink = blocks.vector_sink_c(1024)
            
            # Connect blocks
            self.tb.connect(self.osmosdr_source, self.stream_to_vector)
            self.tb.connect(self.stream_to_vector, self.fft)
            self.tb.connect(self.fft, self.vector_sink)
            
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
        if self.is_running:
            self.tb.stop()
            self.tb.wait()
            self.is_running = False
            logger.info("Stopped RF acquisition")
    
    def get_fft_data(self) -> Optional[np.ndarray]:
        """Get latest FFT data from HackRF"""
        if not self.is_running:
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
        if self.is_running:
            self.osmosdr_source.set_center_freq(freq)
            self.center_freq = freq
            logger.debug(f"Changed frequency to {freq/1e6:.1f} MHz")

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
                'min_hop_rate': 5,
                'max_dwell_time': 2.0,
                'active_probe_threshold': -40,
                'confidence_threshold': 0.7
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
            json.dumps(detection.metadata)
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
        """Handle detection alerts"""
        alert_msg = (f"RF Scanner Detection Alert!\n"
                    f"Type: {detection.detection_type}\n"
                    f"Frequency: {detection.frequency/1e6:.3f} MHz\n"
                    f"Confidence: {detection.confidence:.2f}\n"
                    f"Signal Strength: {detection.signal_strength:.1f} dBm")
        
        logger.warning(alert_msg)
        
        # Additional alerting mechanisms could be added here:
        # - Email notifications
        # - SIEM integration
        # - Slack/Teams notifications
        # - SMS alerts for high-confidence detections
    
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

def main():
    """Main function for running the RF Scanner Detector"""
    import signal
    import sys
    
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
