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
        self.min_hop_rate = 8  # Increased from 5 - hops per second to consider scanning
        self.max_dwell_time = 2.0  # seconds before considering targeted
        self.active_probe_threshold = -20  # Increased from -40 - dBm for active transmission detection
        
        # Calibration period - ignore detections for first 30 seconds
        self.start_time = datetime.now()
        self.calibration_period = 30  # seconds

    def analyze_spectrum(self, fft_data: np.ndarray, center_freq: float) -> List[RFDetection]:
        """Analyze FFT data for scanning patterns"""
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
        """Handle detection alerts with detailed fingerprinting"""
        
        # Get enhanced analysis if advanced features are available
        enhanced_data = self._generate_signal_fingerprint(detection)
        
        # Build comprehensive alert message
        alert_msg = f"""
        ═══════════════════════════════════════════════════════════════
        RF SCANNER DETECTION ALERT
        ═══════════════════════════════════════════════════════════════
        
        BASIC DETECTION INFO:
        ├─ Detection Type: {detection.detection_type.upper()}
        ├─ Timestamp: {detection.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}
        ├─ Frequency: {detection.frequency/1e6:.6f} MHz
        ├─ Signal Strength: {detection.signal_strength:.1f} dBm
        ├─ Confidence Score: {detection.confidence:.3f} ({self._confidence_description(detection.confidence)})
        └─ Duration: {detection.duration:.2f} seconds
        
        SIGNAL FINGERPRINT:
        ├─ Signal-to-Noise Ratio: {enhanced_data.get('snr', 'Unknown'):.1f} dB
        ├─ Bandwidth: {enhanced_data.get('bandwidth', 'Unknown'):.0f} Hz
        ├─ Modulation Type: {enhanced_data.get('modulation_type', 'Unknown')}
        ├─ Rise Time: {enhanced_data.get('rise_time', 'Unknown'):.4f} ms
        ├─ Peak Frequency: {enhanced_data.get('peak_frequency', 'Unknown')/1e6:.6f} MHz
        └─ Signal Stability: {enhanced_data.get('stability_rating', 'Unknown')}
        
        PATTERN ANALYSIS:
        """
        
        # Add detection-specific details
        if detection.detection_type == 'scanning':
            metadata = detection.metadata
            alert_msg += f"""├─ Hop Rate: {metadata.get('hop_rate', 0):.1f} channels/second
        ├─ Frequencies Detected: {metadata.get('frequencies_detected', 0)}
        ├─ Frequency Range: {metadata.get('frequency_range', (0,0))[0]/1e6:.3f} - {metadata.get('frequency_range', (0,0))[1]/1e6:.3f} MHz
        ├─ Channel Spacing: {metadata.get('channel_spacing', 0)/1e3:.1f} kHz
        └─ Scanner Type: {enhanced_data.get('scanner_classification', 'Unknown')}"""
        
        elif detection.detection_type == 'targeted':
            metadata = detection.metadata
            alert_msg += f"""├─ Dwell Time: {metadata.get('dwell_time', 0):.1f} seconds
        ├─ Power Variance: {metadata.get('power_variance', 0):.2f} dB²
        ├─ Sample Count: {metadata.get('sample_count', 0)}
        └─ Monitoring Pattern: {enhanced_data.get('monitoring_pattern', 'Continuous')}"""
        
        elif detection.detection_type == 'active_probe':
            metadata = detection.metadata
            alert_msg += f"""├─ Probe Power: {metadata.get('probe_power', 0):.1f} dBm
        ├─ Above Threshold: {metadata.get('above_threshold', 0):.1f} dB
        ├─ Burst Duration: {detection.duration * 1000:.1f} ms
        └─ Probe Classification: {enhanced_data.get('probe_type', 'Unknown')}"""
        
        # Add threat assessment
        threat_level = self._assess_threat_level(detection, enhanced_data)
        alert_msg += f"""
        
        THREAT ASSESSMENT:
        ├─ Threat Level: {threat_level['level']} ({threat_level['score']:.2f}/10)
        ├─ Likelihood: {threat_level['likelihood']}
        ├─ Recommended Action: {threat_level['recommendation']}
        └─ Follow-up: {threat_level['followup']}
        
        TECHNICAL DETAILS:
        ├─ Center Frequency: {enhanced_data.get('center_frequency', 'Unknown')/1e6:.6f} MHz
        ├─ Frequency Offset: {enhanced_data.get('frequency_offset', 0):.0f} Hz
        ├─ Phase Noise: {enhanced_data.get('phase_noise', 'Unknown'):.3f}
        ├─ Spectral Purity: {enhanced_data.get('spectral_purity', 'Unknown'):.2f}%
        └─ Equipment Signature: {enhanced_data.get('equipment_signature', 'Unknown')}
        
        TIMING ANALYSIS:
        ├─ Detection Latency: {enhanced_data.get('detection_latency', 'Unknown'):.2f} ms
        ├─ Signal Onset: {enhanced_data.get('signal_onset', 'Unknown')}
        └─ Previous Activity: {enhanced_data.get('previous_activity', 'None detected')}
        
        ═══════════════════════════════════════════════════════════════
        """
        
        logger.warning(alert_msg)
        
        # Store enhanced detection data
        self._store_enhanced_detection(detection, enhanced_data)
    
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
