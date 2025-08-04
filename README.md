# RF Scanner Detection System

A passive RF surveillance detection system designed to identify unauthorized radio frequency scanning and monitoring activities using HackRF One SDR hardware with advanced machine learning-based fingerprinting and threat intelligence integration.

## Overview

This system passively monitors RF spectrum to detect when unauthorized parties are scanning or listening for RF transmissions. It provides real-time detection of various scanning patterns with enhanced device fingerprinting, signature clustering, and comprehensive threat assessment across VHF, UHF, and ISM frequency bands.

## Features

### Core Detection Capabilities
- **Sequential Scanner Detection**: Identifies rapid frequency hopping patterns (>8 hops/second)
- **Random Scanner Detection**: Detects erratic frequency jumping characteristic of modern scanners
- **Targeted Monitoring Detection**: Alerts on sustained monitoring of specific frequencies (>10 seconds)
- **Active Probe Detection**: Identifies strong RF transmissions used for direction finding (>-20 dBm)
- **Enhanced Signal Fingerprinting**: Advanced hardware signature analysis using ML clustering

### Advanced Features
- **Device Fingerprinting**: Hardware-specific signature analysis (ADC bits, clock precision, phase noise)
- **Scanner Classification**: Automatic identification of scanner types (consumer, commercial, professional)
- **Signature Clustering**: ML-based grouping of similar scanner signatures using DBSCAN
- **Threat Intelligence Integration**: IOC generation and signature matching against known scanner database
- **SIEM Integration**: Optional integration with security information and event management systems
- **Persistence Tracking**: Long-term device tracking and behavioral analysis

### System Features
- **Real-time Processing**: Continuous monitoring with <100ms detection latency
- **Configurable Frequency Ranges**: Supports VHF, UHF, and custom frequency bands
- **SQLite Database**: Persistent storage of all detection events with enhanced metadata
- **Comprehensive Alerting**: Detailed alerts with hardware analysis and threat assessment
- **Automated Installation**: Smart installer with dependency management and system configuration

## Hardware Requirements

### Essential Hardware
- **HackRF One** SDR device
- **Computer** with USB 3.0 port (Linux/macOS recommended)
- **RF Antenna** appropriate for target frequency ranges

### Recommended Antennas
- **VHF/UHF Discone Antenna**: Wide frequency coverage (25 MHz - 1.3 GHz)
- **Whip Antenna**: Basic coverage for testing
- **Directional Yagi**: Enhanced sensitivity for specific bands

## Software Dependencies

### System Requirements
- **Python 3.8+**
- **GNU Radio 3.8+**
- **HackRF drivers and tools**
- **scikit-learn** (for ML clustering features)

### Python Packages
```bash
pip install numpy scipy matplotlib pandas scikit-learn seaborn requests psutil packaging
```

## Quick Installation

### Automated Installation (Recommended)
```bash
# Download and run the automated installer
git clone https://github.com/sec0ps/rf_surveillance.git
cd rf_surveillance
python3 setup_install.py
```

The installer will:
- Detect your operating system
- Install all system dependencies
- Configure HackRF permissions
- Install Python packages
- Test the installation
- Create desktop shortcuts (Linux)

### Manual Installation

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install gnuradio gnuradio-dev gr-osmosdr hackrf libhackrf-dev git python3-pip python3-dev build-essential cmake pkg-config libusb-1.0-0-dev libudev-dev
pip install -r requirements.txt
```

#### macOS (with Homebrew)
```bash
brew install gnuradio hackrf git python3
pip install -r requirements.txt
```

## Configuration

### Default Configuration
The system automatically creates a comprehensive configuration file with optimal settings for most use cases:

```json
{
  "sample_rate": 2000000,
  "gain": 20,
  "frequency_ranges": [
    [30000000, 50000000],     // VHF Low Band
    [138000000, 174000000],   // VHF High Band
    [420000000, 470000000],   // UHF Business
    [462000000, 467000000],   // GMRS/FRS
    [806000000, 869000000]    // 800 MHz Public Safety
  ],
  "sweep_step": 25000,
  "sweep_dwell_time": 0.5,
  "detection_thresholds": {
    "signal_threshold": -70,
    "min_hop_rate": 8,
    "max_dwell_time": 2.0,
    "active_probe_threshold": -20,
    "confidence_threshold": 0.7
  }
}
```

### Specialized Configurations

#### High-Sensitivity Surveillance Detection
```json
{
  "gain": 30,
  "signal_threshold": -80,
  "min_hop_rate": 5,
  "active_probe_threshold": -30,
  "sweep_dwell_time": 1.0
}
```

#### Fast Sweep for Wide Coverage
```json
{
  "sweep_step": 100000,
  "sweep_dwell_time": 0.2,
  "frequency_ranges": [[30000000, 1000000000]]
}
```

## Usage

### Basic Operation
```bash
# Start detection system
python3 rf_scanner_detection.py

# The system will:
# 1. Initialize HackRF hardware
# 2. Begin frequency sweeping across configured ranges
# 3. Generate enhanced detection alerts with device fingerprinting
# 4. Store results with comprehensive metadata in SQLite database
# 5. Track persistent devices and behavioral patterns
```

### Testing Installation
```bash
# Test system components
python3 setup_install.py --test

# Check prerequisites only
python3 setup_install.py --check
```

## Detection Output

### Enhanced Alert Example
```
═══════════════════════════════════════════════════════════════
RF SCANNER DETECTION ALERT
═══════════════════════════════════════════════════════════════

BASIC DETECTION INFO:
├─ Detection Type: SCANNING
├─ Timestamp: 2025-08-04 12:45:30
├─ Frequency: 462.675000 MHz
├─ Signal Strength: -65.2 dBm
├─ Confidence Score: 0.892 (HIGH)
└─ Duration: 5.00 seconds

ENHANCED DEVICE FINGERPRINT:
├─ Device ID: RF_SCANNER_a1b2c3d4e5f6g7h8
├─ Hardware DC Offset: -42.5 dBm
├─ Estimated ADC Bits: 12
├─ Clock Precision: 100 PPM
├─ Phase Noise: -105.3 dBc/Hz
├─ Image Rejection: 45.2 dB
├─ Spurious Count: 3
├─ Scanner Classification: Commercial Digital Scanner
├─ Equipment Type: Commercial Radio Equipment
└─ Sophistication Level: Commercial Grade

SIGNATURE ANALYSIS:
├─ Known Scanner Matches: 1
├─ uniden_bc125at: 0.847 similarity
└─ IOC Generated: RF_SCAN_a1b2c3d4e5f6g7h8

ENHANCED DEVICE TRACKING:
├─ First Seen: 2025-08-04 12:40:15
├─ Time Active: 0:05:15
├─ Total Detections: 12
├─ Primary Behavior: scanning
├─ Persistence Level: LOW (Brief Activity)
├─ Fingerprint Stability: Stable (Consistent Equipment)
└─ Hardware Type: Standard Digital Scanner

PATTERN ANALYSIS:
├─ Hop Rate: 23.4 channels/second
├─ Frequencies Detected: 117
├─ Frequency Range: 462.550 - 467.725 MHz
└─ Channel Spacing: 25.0 kHz

COMPREHENSIVE THREAT ASSESSMENT:
├─ Threat Score: 6/10
├─ Threat Level: HIGH
├─ Device Category: Commercial Reconnaissance Equipment
├─ Capability Level: Intermediate
├─ Persistence Factor: 0.30
├─ Intelligence Value: Medium - Organized surveillance
└─ Recommendation: Enhanced security measures recommended
═══════════════════════════════════════════════════════════════
```

## Detection Types & Triggers

### 1. Sequential Scanning
**Characteristics**: Rapid, ordered frequency progression with regular channel spacing
**Trigger**: >8 frequency hops per second with consistent channel spacing (12.5/25/50 kHz)
**Enhanced Analysis**: Scan algorithm classification, hop rate stability assessment
**Typical Sources**: Commercial scanners, emergency service monitors

### 2. Random Scanning  
**Characteristics**: Erratic frequency jumping patterns across multiple bands
**Trigger**: Multiple frequency changes with irregular timing patterns
**Enhanced Analysis**: Scan efficiency calculation, memory vs programmed scan detection
**Typical Sources**: Modern digital scanners, SDR-based scanning software

### 3. Targeted Monitoring
**Characteristics**: Sustained presence on specific frequency with low power variance
**Trigger**: >10 seconds continuous monitoring with <5 dB power variance
**Enhanced Analysis**: Monitoring consistency assessment, equipment sophistication analysis
**Typical Sources**: Surveillance equipment, dedicated monitoring receivers

### 4. Active Probes
**Characteristics**: Strong, brief RF transmissions above noise floor
**Trigger**: Signal strength >-20 dBm and >30 dB above noise floor
**Enhanced Analysis**: Direction finding capability assessment, probe type classification
**Typical Sources**: DF equipment, signal analyzers, RF test equipment

## Advanced Features

### Machine Learning Clustering
- **DBSCAN Algorithm**: Groups similar scanner signatures automatically
- **Feature Analysis**: DC offset, ADC bits, phase noise, clock precision
- **Device Classification**: Professional, commercial, consumer equipment categories

### Threat Intelligence
- **IOC Generation**: Creates indicators of compromise for significant detections
- **Signature Database**: Maintains database of known scanner signatures
- **Similarity Matching**: Compares detected signatures against known devices

### Device Tracking
- **Persistent Identification**: Tracks devices across multiple detection sessions
- **Behavioral Analysis**: Identifies primary scanning behaviors and patterns
- **Fingerprint Evolution**: Monitors changes in device signatures over time

## Database Schema

### Detection Records
```sql
CREATE TABLE detections (
    id INTEGER PRIMARY KEY,
    timestamp TEXT,
    frequency REAL,
    signal_strength REAL,
    detection_type TEXT,
    confidence REAL,
    duration REAL,
    metadata TEXT  -- JSON with enhanced fingerprint and tracking data
);
```

### Enhanced Metadata Structure
```json
{
  "enhanced_fingerprint": {
    "device_id": "RF_SCANNER_...",
    "scanner_classification": "Commercial Digital Scanner",
    "sophistication_level": "Commercial Grade",
    "signature_matches": [...],
    "threat_ioc": {...}
  },
  "device_tracking_summary": {
    "detection_count": 15,
    "persistence_level": "MEDIUM",
    "threat_assessment": {...}
  }
}
```

## Performance Specifications

### Real-time Capabilities
- **Processing Latency**: <100ms per FFT frame
- **Sweep Rate**: Configurable 0.1-2.0 seconds per frequency
- **Detection Accuracy**: >95% for signals >-60 dBm
- **False Positive Rate**: <2% with proper baseline configuration

### System Resources
- **CPU Usage**: ~15-25% on modern systems
- **Memory Usage**: ~50-100 MB base, +10 MB per 1000 tracked devices
- **Storage**: ~1 MB per day typical usage, ~10 MB per day high activity

## Operational Considerations

### Legal Compliance
- **Monitor only authorized frequencies** within your organization's spectrum rights
- **Comply with local regulations** regarding passive RF monitoring (typically legal)
- **Document baseline activities** to establish normal RF environment patterns
- **Obtain proper authorization** before deployment in sensitive environments

### Deployment Best Practices

#### Initial Deployment
1. **Baseline Period**: Run for 72 hours to learn normal RF environment
2. **Threshold Tuning**: Adjust detection parameters based on local RF activity
3. **Frequency Optimization**: Focus on bands most relevant to your security concerns
4. **False Positive Analysis**: Review initial detections to identify legitimate sources

#### Production Operation
1. **Continuous Monitoring**: 24/7 operation for comprehensive coverage
2. **Regular Review**: Daily analysis of detection patterns and trends
3. **Database Maintenance**: Implement retention policies (default: 30 days)
4. **Performance Monitoring**: Track system performance metrics

### Environment-Specific Tuning

#### Urban/High RF Environment
```json
{
  "signal_threshold": -65,
  "min_hop_rate": 10,
  "confidence_threshold": 0.8
}
```

#### Rural/Low RF Environment  
```json
{
  "signal_threshold": -75,
  "min_hop_rate": 5,
  "confidence_threshold": 0.6
}
```

## Troubleshooting

### Installation Issues

#### HackRF Not Detected
```bash
# Check USB connection and device recognition
lsusb | grep -i hackrf

# Test HackRF functionality
hackrf_info

# Reset HackRF if needed
hackrf_reset

# Check udev rules (Linux)
ls -la /etc/udev/rules.d/*hackrf*
```

#### GNU Radio Compatibility
```bash
# Test GNU Radio installation
python3 -c "import gnuradio; from gnuradio import gr, blocks; print('GNU Radio OK')"

# Test osmosdr module
python3 -c "import osmosdr; print('OsmoSDR OK')"

# Check version compatibility
python3 setup_install.py --check
```

#### Dependency Issues
```bash
# Install missing Python dependencies
pip install scikit-learn requests packaging

# Update system packages (Ubuntu)
sudo apt update && sudo apt upgrade gnuradio gr-osmosdr
```

### Runtime Issues

#### Poor Detection Performance
- **Increase Gain**: Start with gain=20, increase to 30-40 for weak signals
- **Adjust Thresholds**: Lower signal_threshold for increased sensitivity
- **Antenna Optimization**: Ensure proper antenna for target frequency ranges
- **RF Environment**: Move away from strong RF noise sources

#### False Positives
- **Baseline Learning**: Run system for 72+ hours to establish normal patterns
- **Threshold Tuning**: Increase confidence_threshold and min_hop_rate
- **Frequency Filtering**: Exclude known legitimate transmission frequencies
- **Time-based Filtering**: Consider operational schedules in analysis

#### System Performance
```bash
# Monitor system resources
top -p $(pgrep -f rf_scanner_detection)

# Check log for errors
tail -f rf_scanner_detection.log | grep -E "(ERROR|WARNING)"

# Review detection statistics
tail -f rf_scanner_detection.log | grep "Scanner detected"
```

## Architecture

### Enhanced System Components

#### rf_scanner_detection.py (Main Module)
- **RFSpectrumAnalyzer**: Core signal analysis with ML clustering
- **HackRF Controller**: Hardware interface and GNU Radio flowgraph management
- **RFScannerDetector**: Main system orchestration and configuration
- **ThreatIntelligenceIntegrator**: IOC generation and signature matching
- **SIEMIntegrator**: External security system integration

#### setup_install.py (Installation System)
- **Automated dependency detection and installation**
- **Cross-platform compatibility (Ubuntu/Debian/Fedora/macOS)**
- **HackRF permission configuration**
- **Comprehensive installation testing**

### Enhanced Data Flow
```
HackRF → GNU Radio → FFT Analysis → Pattern Detection → Device Fingerprinting → 
ML Clustering → Signature Matching → Threat Assessment → Alert Generation → 
Database Storage → SIEM Integration
```

## Security Implementation

### Operational Security Features
- **Passive Operation**: Receive-only mode with no RF emissions
- **Signature Obfuscation**: Device fingerprinting to identify surveillance attempts
- **Persistent Tracking**: Long-term monitoring of suspicious devices
- **Threat Scoring**: Comprehensive risk assessment based on device capabilities

### Data Protection
- **Minimal Data Storage**: Only essential detection metadata retained
- **Configurable Retention**: Default 30-day retention with automatic cleanup
- **JSON Serialization**: Secure handling of complex detection metadata
- **Database Integrity**: SQLite with transaction safety

## Integration Options

### SIEM Integration
```python
# Configure SIEM integration
siem_config = {
    'endpoint': 'https://your-siem.com/api/events',
    'api_key': 'your-api-key'
}

siem = SIEMIntegrator(siem_config)
# Automatic event forwarding for detections above threshold
```

### Threat Intelligence Feeds
```python
# Load custom scanner signature database
threat_intel = ThreatIntelligenceIntegrator()
threat_intel.load_scanner_database('custom_scanners.json')
```

## API Reference

### Key Classes and Methods

#### RFSpectrumAnalyzer
```python
analyzer = RFSpectrumAnalyzer(sample_rate=2e6)
detections = analyzer.analyze_spectrum(fft_data, center_freq)
fingerprint = analyzer.generate_enhanced_fingerprint(fft_data, center_freq, metadata)
```

#### Device Tracking
```python
tracked_devices = analyzer.get_tracked_devices()
device_summary = analyzer.device_tracking[device_id]
```

#### Threat Assessment
```python
threat_level = detector._assess_enhanced_threat_level(detection, fingerprint, tracking)
ioc = analyzer.generate_ioc_from_fingerprint(fingerprint, detection_data)
```

## Contributing

### Development Setup
```bash
git clone https://github.com/sec0ps/rf_surveillance.git
cd rf_surveillance
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
```

### Code Standards
- **PEP 8 Compliance**: Follow Python style guidelines
- **Comprehensive Documentation**: Docstrings for all methods
- **Security Focus**: Emphasis on secure coding practices
- **Performance Optimization**: Efficient real-time processing

### Testing
```bash
# Run installation tests
python3 setup_install.py --test

# Manual system validation
python3 rf_scanner_detection.py  # Should start without errors
```

## Professional Services

### Red Cell Security, LLC
For enterprise deployments, custom integrations, or professional security assessments:

- **Email**: keith@redcellsecurity.org
- **Website**: www.redcellsecurity.org
- **Services**: Custom RF security solutions, threat hunting, defensive countermeasures

## Legal Notice

**IMPORTANT**: This system is designed for authorized security operations and legitimate RF monitoring only. Users must ensure compliance with local laws and regulations regarding radio frequency monitoring and electronic surveillance before deployment.

**Typical Legal Status**: Passive RF monitoring (receive-only) is generally legal in most jurisdictions, but users should verify local regulations.

## Disclaimer

This software is provided "as-is," without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement. In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.

## License & Copyright

**Author**: Keith Pachulski  
**Company**: Red Cell Security, LLC  
**Email**: keith@redcellsecurity.org  
**Website**: www.redcellsecurity.org  

© 2025 Keith Pachulski. All rights reserved.

**License**: MIT License - You are free to use, modify, and distribute this software in accordance with the terms of the license.

## Support Development

If you find this project valuable for your security operations:

[![Donate](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://paypal.me/sec0ps)

---

**⚠️ Security Notice**: This system detects unauthorized RF surveillance activities. Deploy as part of a comprehensive communications security (COMSEC) program for maximum effectiveness.

## Support My Work

If you find my work useful and want to support continued development, you can donate here:

[![Donate](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://paypal.me/sec0ps)

> **DISCLAIMER**:  
> This software is provided "as-is," without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement. In no event shall the authors or copyright holders
> be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.
> This tool is for educational and research purposes only. Users are responsible for how they deploy and use this honeypot system. Always obtain proper authorization before deploying honeypots in production environments.

---

**⚠️ Important**: This system is designed for legitimate security operations and authorized RF monitoring only. Ensure compliance with local laws and regulations before deployment.
