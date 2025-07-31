# RF Scanner Detection System

A passive RF surveillance detection system designed to identify malicious radio frequency scanning and monitoring activities using HackRF One SDR hardware.

## Overview

This system passively monitors RF spectrum to detect when unauthorized parties are scanning or listening for RF transmissions. It can identify various scanning patterns including sequential scanning, random scanning, targeted monitoring, and active RF probes across VHF, UHF, and ISM frequency bands.

## Features

### Core Detection Capabilities
- **Sequential Scanner Detection**: Identifies rapid frequency hopping patterns (>5 hops/second)
- **Random Scanner Detection**: Detects erratic frequency jumping characteristic of modern scanners
- **Targeted Monitoring Detection**: Alerts on sustained monitoring of specific frequencies (>10 seconds)
- **Active Probe Detection**: Identifies strong, brief RF transmissions used for direction finding
- **Signal Fingerprinting**: Analyzes modulation characteristics to identify scanner device types

### System Features
- **Real-time Processing**: Continuous monitoring with <100ms detection latency
- **Configurable Frequency Ranges**: Supports VHF, UHF, and custom frequency bands
- **SQLite Database**: Persistent storage of all detection events
- **Advanced Analytics**: Signal signature analysis and threat intelligence integration
- **Comprehensive Reporting**: HTML reports with visualizations and threat assessments
- **Automated Alerting**: Log-based alerts with configurable thresholds

## Hardware Requirements

### Essential Hardware
- **HackRF One** SDR device
- **Computer** with USB 3.0 port (Linux/macOS/Windows)
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

### Python Packages
```bash
pip install numpy scipy matplotlib pandas sqlite3 scikit-learn seaborn
```

## Installation

### 1. Install System Dependencies

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install gnuradio gnuradio-dev gr-osmosdr hackrf libhackrf-dev hackrf-tools
```

#### macOS (with Homebrew)
```bash
brew install gnuradio hackrf
```

#### Windows
- Install GNU Radio from official website
- Install HackRF drivers using Zadig tool

### 2. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 3. Verify HackRF Connection
```bash
hackrf_info
```

### 4. Clone Repository
```bash
git clone https://github.com/sec0ps/rf_surveillance.git
cd rf-scanner-detection
```

## Configuration

### Basic Configuration (rf_config.json)
```json
{
  "sample_rate": 2000000,
  "gain": 20,
  "frequency_ranges": [
    [144000000, 174000000],
    [420000000, 450000000],
    [462000000, 467000000]
  ],
  "sweep_step": 1000000,
  "sweep_dwell_time": 0.5,
  "detection_thresholds": {
    "signal_threshold": -70,
    "min_hop_rate": 5,
    "max_dwell_time": 2.0,
    "active_probe_threshold": -40
  }
}
```

### Frequency Band Examples

#### Public Safety Monitoring
```json
"frequency_ranges": [
  [154000000, 158000000],  // VHF Fire/EMS
  [453000000, 458000000],  // UHF Police
  [460000000, 470000000]   // UHF Fire/EMS
]
```

#### Commercial Radio Monitoring
```json
"frequency_ranges": [
  [144000000, 148000000],  // VHF Business
  [450000000, 470000000],  // UHF Business
  [462562500, 467712500]   // GMRS/FRS
]
```

## Usage

### Basic Operation
```bash
# Start detection system
python3 rf_scanner_detection.py

# The system will:
# 1. Initialize HackRF hardware
# 2. Begin frequency sweeping
# 3. Log detections to console and file
# 4. Store results in SQLite database
```

### Advanced Usage

#### Run Comprehensive Tests
```bash
python3 testing_framework.py
```

#### Generate Threat Report
```python
from rf_advanced_features import ReportingAndVisualization
from rf_scanner_detection import RFScannerDetector

detector = RFScannerDetector()
detections = detector.get_recent_detections(hours=24)

reporting = ReportingAndVisualization()
report = reporting.generate_threat_report(detections)
print(f"Report generated: {report}")
```

#### Custom Detection Analysis
```python
from rf_advanced_features import AdvancedSignalAnalyzer

analyzer = AdvancedSignalAnalyzer()
# Analyze IQ data for device fingerprinting
signature = analyzer.analyze_modulation_signature(iq_data, sample_rate)
```

## Detection Types

### 1. Sequential Scanning
**Characteristics**: Rapid, ordered frequency progression
**Trigger**: >5 frequency hops per second in sequence
**Typical Sources**: Police scanners, emergency service scanners

### 2. Random Scanning  
**Characteristics**: Erratic frequency jumping patterns
**Trigger**: Multiple frequency changes with random timing
**Typical Sources**: Modern digital scanners, SDR-based scanners

### 3. Targeted Monitoring
**Characteristics**: Sustained presence on specific frequency
**Trigger**: >10 seconds continuous monitoring of single frequency
**Typical Sources**: Surveillance equipment, dedicated monitors

### 4. Active Probes
**Characteristics**: Strong, brief RF transmissions
**Trigger**: Signal strength >-40 dBm for <100ms duration
**Typical Sources**: Direction finding equipment, signal analyzers

## Output and Alerts

### Console Output
```
2024-01-15 14:23:45 - RF Scanner Detection Alert!
Type: scanning
Frequency: 462.675 MHz
Confidence: 0.87
Signal Strength: -62.3 dBm
```

### Database Storage
All detections are stored in `rf_detections.db` with:
- Timestamp
- Frequency
- Signal strength
- Detection type
- Confidence score
- Duration
- Metadata (hop rates, patterns, etc.)

### HTML Reports
Generated reports include:
- Detection timeline charts
- Frequency distribution analysis
- Confidence vs signal strength plots
- Threat level assessment
- Actionable recommendations

## Operational Considerations

### Legal Compliance
- **Monitor only authorized frequencies** for your organization
- **Comply with local regulations** regarding RF monitoring
- **Document legitimate usage** to reduce false positives
- **Obtain proper authorization** before deployment

### Performance Optimization

#### High Sensitivity Setup
```json
{
  "gain": 40,
  "signal_threshold": -80,
  "sweep_dwell_time": 2.0
}
```

#### Fast Sweep Setup
```json
{
  "sweep_step": 5000000,
  "sweep_dwell_time": 0.1,
  "frequency_ranges": [[30000000, 1000000000]]
}
```

### False Positive Reduction
1. **Baseline Period**: Run for 72 hours to learn normal RF environment
2. **Whitelist Frequencies**: Identify and exclude legitimate transmissions
3. **Threshold Tuning**: Adjust detection parameters based on environment
4. **Time-based Filtering**: Consider operational schedules and patterns

## Troubleshooting

### Common Issues

#### HackRF Not Detected
```bash
# Check USB connection
lsusb | grep HackRF

# Reset HackRF
hackrf_reset

# Check permissions (Linux)
sudo usermod -a -G plugdev $USER
```

#### GNU Radio Errors
```bash
# Verify installation
python3 -c "import gnuradio; print('GNU Radio OK')"
python3 -c "import osmosdr; print('OsmoSDR OK')"

# Reinstall if needed
sudo apt install --reinstall gr-osmosdr
```

#### Poor Detection Performance
- **Increase gain**: Higher gain for weak signals
- **Adjust thresholds**: Lower signal threshold for sensitivity
- **Check antenna**: Ensure proper antenna for frequency range
- **Reduce interference**: Move away from RF noise sources

### Log Analysis
```bash
# Check recent errors
tail -f rf_scanner_detection.log | grep ERROR

# Review detection patterns
tail -f rf_scanner_detection.log | grep "Scanner detected"
```

## Architecture

### Core Modules

#### rf_scanner_detection.py
- Main detection engine
- HackRF hardware control
- Pattern recognition algorithms
- Database operations

#### rf_advanced_features.py
- Signal signature analysis
- Device fingerprinting
- Threat intelligence integration
- Advanced reporting

#### testing_framework.py
- Comprehensive test suite
- Performance validation
- Hardware integration tests
- Synthetic signal generation

### System Flow
```
HackRF → GNU Radio → FFT Analysis → Pattern Detection → Alert Generation → Database Storage
```

## Contributing

### Development Setup
```bash
git clone <repository-url>
cd rf-scanner-detection
pip install -r requirements-dev.txt
python3 -m pytest tests/
```

### Code Style
- Follow PEP 8 guidelines
- Include docstrings for all functions
- Add unit tests for new features
- Update documentation for changes

## Security Considerations

### Operational Security
- **No RF Emissions**: System operates in receive-only mode
- **Encrypted Storage**: Consider encrypting detection database
- **Access Control**: Restrict system access to authorized personnel
- **Secure Deployment**: Use dedicated, hardened systems

### Data Protection
- **Minimize Data**: Store only necessary detection metadata
- **Regular Cleanup**: Implement data retention policies
- **Secure Transfer**: Use encrypted channels for remote access

## Disclaimer

This tool is for educational and research purposes only. Users are responsible for how they deploy and use this system. Always obtain proper authorization before deploying in production environments.

## Contact
For professional services, integrations, or support contact: operations@redcellsecurity.org

## License

**Author**: Keith Pachulski  
**Company**: Red Cell Security, LLC  
**Email**: keith@redcellsecurity.org  
**Website**: www.redcellsecurity.org  

© 2025 Keith Pachulski. All rights reserved.

**License**: This software is licensed under the MIT License. You are free to use, modify, and distribute this software in accordance with the terms of the license.

## Support My Work

If you find my work useful and want to support continued development, you can donate here:

[![Donate](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://paypal.me/sec0ps)

> **DISCLAIMER**:  
> This software is provided "as-is," without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement. In no event shall the authors or copyright holders
> be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.
> This tool is for educational and research purposes only. Users are responsible for how they deploy and use this honeypot system. Always obtain proper authorization before deploying honeypots in production environments.

---

**⚠️ Important**: This system is designed for legitimate security operations and authorized RF monitoring only. Ensure compliance with local laws and regulations before deployment.
