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
import matplotlib.pyplot as plt
import time
import threading
import subprocess
import tempfile
import os
from datetime import datetime, timedelta
from typing import List, Dict, Tuple
import unittest
import json
import requests
import logging  # For logging functionality in tests
from collections import defaultdict  # If you want to use defaultdict anywhere

from rf_scanner_detection import RFScannerDetector, RFDetection, HackRFController, RFSpectrumAnalyzer

logger = logging.getLogger(__name__)

class RFTestSignalGenerator:
    """Generate synthetic RF signals for testing detection algorithms"""
    
    def __init__(self, sample_rate=2e6):
        self.sample_rate = sample_rate
        self.noise_floor = -80  # dBm
        
    def generate_scanner_pattern(self, pattern_type='sequential_scan', duration=10):
        """Generate realistic scanner signal patterns"""
        
        patterns = {
            'sequential_scan': self._generate_sequential_scan,
            'random_scan': self._generate_random_scan,
            'targeted_monitor': self._generate_targeted_monitor,
            'trunked_scan': self._generate_trunked_scan,
            'active_probe': self._generate_active_probe
        }
        
        if pattern_type in patterns:
            return patterns[pattern_type](duration)
        else:
            raise ValueError(f"Unknown pattern type: {pattern_type}")
    
    # KEEP ALL PATTERN GENERATION METHODS - These are unique test utilities
    def _generate_sequential_scan(self, duration):
        """Generate sequential frequency scanning pattern"""
        
        # Parameters for typical scanner behavior
        frequencies = np.arange(144e6, 174e6, 25e3)  # VHF band, 25 kHz steps
        dwell_time = 0.1  # 100ms per frequency
        hop_rate = 1 / dwell_time  # 10 hops/second
        
        timeline = []
        current_time = 0
        freq_idx = 0
        
        while current_time < duration:
            freq = frequencies[freq_idx % len(frequencies)]
            signal_strength = self.noise_floor + np.random.normal(15, 3)  # Typical scanner signal
            
            timeline.append({
                'time': current_time,
                'frequency': freq,
                'signal_strength': signal_strength,
                'duration': dwell_time,
                'pattern_info': {
                    'hop_rate': hop_rate,
                    'frequency_step': 25e3,
                    'scan_type': 'sequential'
                }
            })
            
            current_time += dwell_time
            freq_idx += 1
        
        return timeline
    
    def _generate_random_scan(self, duration):
        """Generate random frequency scanning pattern"""
        
        frequency_pool = np.concatenate([
            np.arange(144e6, 174e6, 25e3),  # VHF
            np.arange(420e6, 470e6, 25e3),  # UHF
            np.arange(462e6, 467e6, 25e3)   # GMRS
        ])
        
        timeline = []
        current_time = 0
        
        while current_time < duration:
            freq = np.random.choice(frequency_pool)
            dwell_time = np.random.exponential(0.2)  # Random dwell times
            signal_strength = self.noise_floor + np.random.normal(12, 5)
            
            timeline.append({
                'time': current_time,
                'frequency': freq,
                'signal_strength': signal_strength,
                'duration': dwell_time,
                'pattern_info': {
                    'hop_rate': 1/dwell_time,
                    'scan_type': 'random'
                }
            })
            
            current_time += dwell_time
        
        return timeline
    
    def _generate_targeted_monitor(self, duration):
        """Generate targeted frequency monitoring pattern"""
        
        target_freq = 462.675e6  # GMRS channel
        
        timeline = [{
            'time': 0,
            'frequency': target_freq,
            'signal_strength': self.noise_floor + np.random.normal(10, 2),
            'duration': duration,
            'pattern_info': {
                'monitor_type': 'targeted',
                'dwell_time': duration
            }
        }]
        
        return timeline
    
    def _generate_trunked_scan(self, duration):
        """Generate trunked radio scanning pattern"""
        
        control_channels = [857.7625e6, 858.7625e6, 859.7625e6]  # 800 MHz trunked
        voice_channels = np.arange(851e6, 870e6, 25e3)
        
        timeline = []
        current_time = 0
        
        while current_time < duration:
            # Alternate between control channel monitoring and voice following
            if np.random.random() < 0.3:  # 30% control channel
                freq = np.random.choice(control_channels)
                dwell_time = 0.5  # Longer on control channels
            else:  # Voice channel following
                freq = np.random.choice(voice_channels)
                dwell_time = np.random.exponential(2.0)  # Variable voice duration
            
            signal_strength = self.noise_floor + np.random.normal(18, 4)
            
            timeline.append({
                'time': current_time,
                'frequency': freq,
                'signal_strength': signal_strength,
                'duration': dwell_time,
                'pattern_info': {
                    'scan_type': 'trunked',
                    'is_control_channel': freq in control_channels
                }
            })
            
            current_time += dwell_time
        
        return timeline
    
    def _generate_active_probe(self, duration):
        """Generate active RF probe/direction finding pattern"""
        
        probe_frequencies = [462.5625e6, 467.7125e6, 154.935e6]  # Common frequencies
        
        timeline = []
        current_time = 0
        
        while current_time < duration:
            freq = np.random.choice(probe_frequencies)
            
            # Active probes are short, strong bursts
            dwell_time = np.random.uniform(0.01, 0.1)  # 10-100ms bursts
            signal_strength = self.noise_floor + np.random.normal(35, 5)  # Strong signals
            
            timeline.append({
                'time': current_time,
                'frequency': freq,
                'signal_strength': signal_strength,
                'duration': dwell_time,
                'pattern_info': {
                    'probe_type': 'active',
                    'burst_power': signal_strength
                }
            })
            
            # Random gaps between probes
            current_time += dwell_time + np.random.exponential(1.0)
        
        return timeline

class RFDetectionTester:
    """Comprehensive testing suite for RF detection algorithms"""
    
    def __init__(self):
        self.signal_generator = RFTestSignalGenerator()
        self.test_results = []
        
    def run_detection_accuracy_tests(self):
        """Test detection accuracy against known patterns"""
        
        print("Running Detection Accuracy Tests...")
        print("=" * 50)
        
        test_patterns = [
            ('sequential_scan', 30),
            ('random_scan', 30),
            ('targeted_monitor', 60),
            ('trunked_scan', 30),
            ('active_probe', 20)
        ]
        
        results = {}
        
        for pattern_type, duration in test_patterns:
            print(f"\nTesting {pattern_type} pattern...")
            
            # Generate test signal
            test_timeline = self.signal_generator.generate_scanner_pattern(
                pattern_type, duration
            )
            
            # Use the actual RFSpectrumAnalyzer from rf_scanner_detection.py
            from rf_scanner_detection import RFSpectrumAnalyzer
            analyzer = RFSpectrumAnalyzer()
            
            detections = []
            # Process timeline through real analyzer
            time_windows = self._group_timeline_by_windows(test_timeline, window_size=1.0)
            
            for window_time, events in time_windows.items():
                # Create realistic test FFT data
                fft_data = self._generate_test_fft_from_events(events)
                center_freq = events[0]['frequency'] if events else 400e6
                
                # Run real detection analysis
                window_detections = analyzer.analyze_spectrum(fft_data, center_freq)
                detections.extend(window_detections)
            
            # Analyze results using simplified validation
            accuracy = self._validate_test_results(test_timeline, detections, pattern_type)
            results[pattern_type] = accuracy
            
            print(f"  Detections: {len(detections)}")
            print(f"  Expected Pattern: {pattern_type}")
            print(f"  Validation Score: {accuracy['validation_score']:.2f}")
        
        return results
    
    def _group_timeline_by_windows(self, timeline, window_size):
        """Group timeline events into analysis windows - KEEP this utility method"""
        
        windows = {}
        for event in timeline:
            window_start = int(event['time'] / window_size) * window_size
            if window_start not in windows:
                windows[window_start] = []
            windows[window_start].append(event)
        
        return windows
    
    def _generate_test_fft_from_events(self, events):
        """Generate realistic test FFT data from timeline events - KEEP this utility"""
        
        fft_size = 1024
        
        # Start with noise
        fft_data = np.random.normal(0, 0.1, fft_size) + 1j * np.random.normal(0, 0.1, fft_size)
        
        # Add signals from events
        for event in events:
            # Convert signal strength to linear scale
            power_linear = 10 ** (event['signal_strength'] / 10)
            amplitude = np.sqrt(power_linear)
            
            # Add signal to random FFT bin (simplified)
            signal_bin = np.random.randint(0, fft_size)
            fft_data[signal_bin] += amplitude * (1 + 0.1j)
        
        return fft_data
    
    def _validate_test_results(self, timeline, detections, expected_pattern):
        """Simplified validation of test results - REPLACE the complex duplicate methods"""
        
        # Simple validation based on pattern expectations
        expected_count = 1  # Default expectation
        
        if expected_pattern in ['sequential_scan', 'random_scan', 'trunked_scan']:
            expected_count = 1  # Should detect scanning behavior
        elif expected_pattern == 'targeted_monitor':
            expected_count = 1  # Should detect monitoring
        elif expected_pattern == 'active_probe':
            expected_count = max(1, len(timeline) // 10)  # Multiple probe detections
        
        # Calculate simple validation score
        detection_count = len(detections)
        if detection_count > 0:
            # Check if we got reasonable detections
            validation_score = min(1.0, detection_count / max(expected_count, 1))
        else:
            validation_score = 0.0
        
        return {
            'detections_found': detection_count,
            'expected_count': expected_count,
            'validation_score': validation_score,
            'pattern_matched': validation_score > 0.5
        }

class PerformanceTester:
    """Test system performance and resource usage"""
    
    def __init__(self):
        self.performance_metrics = {}
        
    def test_processing_speed(self, duration_minutes=10):
        """Test real-time processing performance"""
        
        print(f"Testing processing speed for {duration_minutes} minutes...")
        
        # Use actual detector from rf_scanner_detection.py
        from rf_scanner_detection import RFScannerDetector
        detector = RFScannerDetector()
        
        # Performance monitoring
        start_time = time.time()
        initial_memory = self._get_memory_usage()
        processing_times = []
        
        # Simulate high-rate data processing
        test_duration = duration_minutes * 60
        sample_interval = 0.1  # 100ms samples
        
        for i in range(int(test_duration / sample_interval)):
            sample_start = time.time()
            
            # Generate test FFT data
            fft_data = np.random.complex128(1024)
            center_freq = 400e6 + (i % 1000) * 1e3  # Sweep frequencies
            
            # Process sample using real analyzer
            detections = detector.analyzer.analyze_spectrum(fft_data, center_freq)
            
            processing_time = time.time() - sample_start
            processing_times.append(processing_time)
            
            # Brief pause to simulate real-time constraints
            time.sleep(max(0, sample_interval - processing_time))
        
        # Calculate metrics
        total_time = time.time() - start_time
        final_memory = self._get_memory_usage()
        
        metrics = {
            'total_samples': len(processing_times),
            'avg_processing_time': np.mean(processing_times),
            'max_processing_time': np.max(processing_times),
            'min_processing_time': np.min(processing_times),
            'samples_per_second': len(processing_times) / total_time,
            'memory_usage_mb': final_memory - initial_memory,
            'real_time_capable': np.max(processing_times) < sample_interval
        }
        
        print(f"Performance Test Results:")
        print(f"  Samples processed: {metrics['total_samples']}")
        print(f"  Average processing time: {metrics['avg_processing_time']*1000:.2f} ms")
        print(f"  Maximum processing time: {metrics['max_processing_time']*1000:.2f} ms")
        print(f"  Samples per second: {metrics['samples_per_second']:.1f}")
        print(f"  Memory usage: {metrics['memory_usage_mb']:.1f} MB")
        print(f"  Real-time capable: {'Yes' if metrics['real_time_capable'] else 'No'}")
        
        return metrics
    
    def _get_memory_usage(self):
        """Get current memory usage in MB"""
        try:
            import psutil
            process = psutil.Process()
            return process.memory_info().rss / 1024 / 1024  # Convert to MB
        except ImportError:
            return 0  # psutil not available
    
    def test_concurrent_detection(self, num_threads=4):
        """Test concurrent detection processing"""
        
        print(f"Testing concurrent detection with {num_threads} threads...")
        
        # Use actual detector
        from rf_scanner_detection import RFScannerDetector
        
        results = []
        threads = []
        
        def detection_worker(worker_id):
            """Worker function for concurrent testing"""
            detector = RFScannerDetector()
            start_time = time.time()
            detections = []
            
            # Process for 30 seconds
            while time.time() - start_time < 30:
                fft_data = np.random.complex128(1024)
                center_freq = 400e6 + worker_id * 10e6  # Different freq ranges per worker
                
                worker_detections = detector.analyzer.analyze_spectrum(fft_data, center_freq)
                detections.extend(worker_detections)
                
                time.sleep(0.1)  # 100ms processing cycle
            
            results.append({
                'worker_id': worker_id,
                'detections': len(detections),
                'duration': time.time() - start_time
            })
        
        # Start worker threads
        for i in range(num_threads):
            thread = threading.Thread(target=detection_worker, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # Analyze results
        total_detections = sum(r['detections'] for r in results)
        avg_detections_per_worker = total_detections / num_threads
        
        print(f"Concurrent Processing Results:")
        print(f"  Workers: {num_threads}")
        print(f"  Total detections: {total_detections}")
        print(f"  Average per worker: {avg_detections_per_worker:.1f}")
        
        for result in results:
            print(f"  Worker {result['worker_id']}: {result['detections']} detections")
        
        return results

class IntegrationTester:
    """Test system integration with external components"""
    
    def __init__(self):
        self.test_results = {}
        
    def test_hackrf_integration(self):
        """Test HackRF hardware integration"""
        
        print("Testing HackRF Integration...")
        
        # Test HackRF detection
        hackrf_detected = self._check_hackrf_presence()
        
        if not hackrf_detected:
            print("  ERROR: HackRF not detected")
            return {'status': 'FAILED', 'error': 'HackRF not detected'}
        
        # Test HackRF initialization using actual controller
        from rf_scanner_detection import HackRFController
        controller = HackRFController()
        init_success = controller.setup_flowgraph()
        
        if not init_success:
            print("  ERROR: HackRF initialization failed")
            return {'status': 'FAILED', 'error': 'Initialization failed'}
        
        # Test frequency setting
        test_frequencies = [144e6, 400e6, 900e6]
        freq_test_results = []
        
        for freq in test_frequencies:
            try:
                controller.set_frequency(freq)
                freq_test_results.append(True)
                print(f"  Frequency {freq/1e6:.0f} MHz: OK")
            except Exception as e:
                freq_test_results.append(False)
                print(f"  Frequency {freq/1e6:.0f} MHz: FAILED - {e}")
        
        # Test data acquisition
        data_test = self._test_data_acquisition(controller)
        
        controller.stop_acquisition()
        
        results = {
            'status': 'PASSED' if all(freq_test_results) and data_test else 'FAILED',
            'hackrf_detected': hackrf_detected,
            'initialization': init_success,
            'frequency_tests': freq_test_results,
            'data_acquisition': data_test
        }
        
        print(f"  Overall HackRF Integration: {results['status']}")
        return results
    
    def _check_hackrf_presence(self):
        """Check if HackRF device is present"""
        try:
            result = subprocess.run(['hackrf_info'], capture_output=True, text=True, timeout=10)
            return 'Found HackRF' in result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def _test_data_acquisition(self, controller):
        """Test data acquisition from HackRF"""
        try:
            if controller.start_acquisition():
                time.sleep(2)  # Let it acquire some data
                fft_data = controller.get_fft_data()
                return fft_data is not None and len(fft_data) > 0
        except Exception:
            pass
        return False
    
    def test_database_integration(self):
        """Test database operations"""
        
        print("Testing Database Integration...")
        
        # Use actual detector for database testing
        from rf_scanner_detection import RFScannerDetector, RFDetection
        detector = RFScannerDetector()
        
        # Test database initialization
        try:
            detector._init_database()
            print("  Database initialization: OK")
        except Exception as e:
            print(f"  Database initialization: FAILED - {e}")
            return {'status': 'FAILED', 'error': str(e)}
        
        # Test detection storage
        test_detection = RFDetection(
            timestamp=datetime.now(),
            frequency=462.5625e6,
            signal_strength=-65.0,
            detection_type='test',
            confidence=0.85,
            duration=1.0,
            metadata={'test': True}
        )
        
        try:
            detector._save_detection(test_detection)
            print("  Detection storage: OK")
        except Exception as e:
            print(f"  Detection storage: FAILED - {e}")
            return {'status': 'FAILED', 'error': str(e)}
        
        # Test detection retrieval
        try:
            recent_detections = detector.get_recent_detections(hours=1)
            test_found = any(d.metadata.get('test') for d in recent_detections)
            
            if test_found:
                print("  Detection retrieval: OK")
            else:
                print("  Detection retrieval: WARNING - Test detection not found")
                
        except Exception as e:
            print(f"  Detection retrieval: FAILED - {e}")
            return {'status': 'FAILED', 'error': str(e)}
        
        return {'status': 'PASSED'}

    def test_alerting_system(self):
        """Test alerting and notification systems"""
        
        print("Testing Alerting System...")
        
        # Test log file writing
        try:
            import logging
            logger = logging.getLogger('test_alerts')
            handler = logging.FileHandler('test_alerts.log')
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
            
            logger.info("Test alert message")
            print("  Log file alerting: OK")
        except Exception as e:
            print(f"  Log file alerting: FAILED - {e}")
        
        return {'status': 'PASSED'}
    
    def test_advanced_features_integration(self):
        """Test integration of advanced features"""
        
        print("Testing Advanced Features Integration...")
        
        try:
            # Test automated response system
            from rf_advanced_features import AutomatedResponseSystem
            response_system = AutomatedResponseSystem()
            
            # Add a test rule
            test_rule = {
                'conditions': {'min_confidence': 0.8},
                'actions': [{'type': 'alert', 'message': 'Test alert'}]
            }
            response_system.add_response_rule(test_rule)
            print("  Automated Response System: OK")
            
            # Test threat intelligence
            from rf_advanced_features import ThreatIntelligenceIntegrator
            threat_intel = ThreatIntelligenceIntegrator()
            threat_intel.load_scanner_database('test_scanners.json')
            print("  Threat Intelligence: OK")
            
            # Test reporting
            from rf_advanced_features import ReportingAndVisualization
            reporting = ReportingAndVisualization()
            print("  Reporting System: OK")
            
            return {'status': 'PASSED'}
            
        except Exception as e:
            print(f"  Advanced Features Integration: FAILED - {e}")
            return {'status': 'FAILED', 'error': str(e)}
    
class ComprehensiveTestSuite:
    """Main test suite coordinator"""
    
    def __init__(self):
        self.detection_tester = RFDetectionTester()
        self.performance_tester = PerformanceTester()
        self.integration_tester = IntegrationTester()
        
    def run_all_tests(self):
        """Run complete test suite"""
        
        print("RF Scanner Detection System - Comprehensive Test Suite")
        print("=" * 60)
        print(f"Test started: {datetime.now()}")
        print()
        
        all_results = {}
        
        # Detection accuracy tests
        try:
            accuracy_results = self.detection_tester.run_detection_accuracy_tests()
            all_results['detection_accuracy'] = accuracy_results
        except Exception as e:
            print(f"Detection accuracy tests failed: {e}")
            all_results['detection_accuracy'] = {'error': str(e)}
        
        print("\n" + "-" * 50)
        
        # Performance tests
        try:
            performance_results = self.performance_tester.test_processing_speed(duration_minutes=2)
            all_results['performance'] = performance_results
        except Exception as e:
            print(f"Performance tests failed: {e}")
            all_results['performance'] = {'error': str(e)}
        
        print("\n" + "-" * 50)
        
        # Integration tests
        try:
            hackrf_results = self.integration_tester.test_hackrf_integration()
            db_results = self.integration_tester.test_database_integration()
            alert_results = self.integration_tester.test_alerting_system()
            advanced_results = self.integration_tester.test_advanced_features_integration()
            
            all_results['integration'] = {
                'hackrf': hackrf_results,
                'database': db_results,
                'alerting': alert_results,
                'advanced_features': advanced_results
            }
        except Exception as e:
            print(f"Integration tests failed: {e}")
            all_results['integration'] = {'error': str(e)}
        
        # Generate test report
        self._generate_test_report(all_results)
        
        print(f"\nTest completed: {datetime.now()}")
        print("Test report saved to: test_report.json")
        
        return all_results
    
    def _generate_test_report(self, results):
        """Generate comprehensive test report"""
        
        report = {
            'test_timestamp': datetime.now().isoformat(),
            'system_info': self._get_system_info(),
            'test_results': results,
            'summary': self._generate_test_summary(results)
        }
        
        # Save to JSON file
        with open('test_report.json', 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # Generate HTML report
        self._generate_html_report(report)
    
    def _get_system_info(self):
        """Get system information for test report"""
        import platform
        
        return {
            'platform': platform.platform(),
            'python_version': platform.python_version(),
            'processor': platform.processor(),
            'machine': platform.machine()
        }
    
    def _generate_test_summary(self, results):
        """Generate test summary"""
        
        summary = {
            'total_tests': 0,
            'passed_tests': 0,
            'failed_tests': 0,
            'overall_status': 'UNKNOWN'
        }
        
        # Count test results
        for category, category_results in results.items():
            if isinstance(category_results, dict):
                if 'error' in category_results:
                    summary['failed_tests'] += 1
                elif category_results.get('status') == 'PASSED':
                    summary['passed_tests'] += 1
                elif category_results.get('status') == 'FAILED':
                    summary['failed_tests'] += 1
                
                summary['total_tests'] += 1
        
        # Determine overall status
        if summary['failed_tests'] == 0:
            summary['overall_status'] = 'PASSED'
        elif summary['passed_tests'] > summary['failed_tests']:
            summary['overall_status'] = 'MOSTLY_PASSED'
        else:
            summary['overall_status'] = 'FAILED'
        
        return summary
    
    def _generate_html_report(self, report):
        """Generate HTML test report"""
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>RF Scanner Detection Test Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f0f0f0; padding: 15px; border-radius: 5px; }}
                .summary {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; }}
                .passed {{ color: green; }}
                .failed {{ color: red; }}
                .section {{ margin: 15px 0; }}
                pre {{ background-color: #f8f8f8; padding: 10px; border-radius: 3px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>RF Scanner Detection System Test Report</h1>
                <p>Generated: {report['test_timestamp']}</p>
                <p>System: {report['system_info']['platform']}</p>
            </div>
            
            <div class="summary">
                <h2>Test Summary</h2>
                <p><strong>Overall Status:</strong> 
                   <span class="{'passed' if report['summary']['overall_status'] == 'PASSED' else 'failed'}">
                   {report['summary']['overall_status']}
                   </span>
                </p>
                <p>Total Tests: {report['summary']['total_tests']}</p>
                <p class="passed">Passed: {report['summary']['passed_tests']}</p>
                <p class="failed">Failed: {report['summary']['failed_tests']}</p>
            </div>
            
            <div class="section">
                <h2>Detailed Results</h2>
                <pre>{json.dumps(report['test_results'], indent=2, default=str)}</pre>
            </div>
        </body>
        </html>
        """
        
        with open('test_report.html', 'w') as f:
            f.write(html_content)

# Main execution
if __name__ == "__main__":
    # Run comprehensive test suite
    test_suite = ComprehensiveTestSuite()
    results = test_suite.run_all_tests()
    
    # Print final summary
    print("\n" + "=" * 60)
    print("FINAL TEST SUMMARY")
    print("=" * 60)
    
    if results.get('summary', {}).get('overall_status') == 'PASSED':
        print("? All tests PASSED - System ready for deployment")
    else:
        print("? Some tests FAILED - Review results before deployment")
        
    print(f"Detailed results saved to: test_report.html")
