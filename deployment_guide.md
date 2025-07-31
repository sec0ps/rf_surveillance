# RF Scanner Detection System Setup Guide

## Prerequisites and Installation

### 1. Hardware Requirements
- **HackRF One** SDR device
- **Laptop/Computer** with USB 3.0 port
- **RF Antenna** appropriate for target frequency ranges
- **Optional**: External amplifier for weak signal detection

### 2. Software Dependencies

#### Install GNU Radio (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install gnuradio gnuradio-dev gr-osmosdr
```

#### Install GNU Radio (macOS with Homebrew)
```bash
brew install gnuradio
```

#### Install Python Dependencies
```bash
pip install numpy scipy matplotlib sqlite3 threading queue dataclasses
```

#### HackRF Drivers and Tools
```bash
# Ubuntu/Debian
sudo apt install hackrf libhackrf-dev hackrf-tools

# macOS
brew install hackrf

# Test HackRF connection
hackrf_info
```

### 3. Configuration File Setup

Create `rf_config.json` in your project directory:

```json
{
  "sample_rate": 2000000,
  "gain": 20,
  "frequency_ranges": [
    [30000000, 50000000],      
    [144000000, 174000000],    
    [420000000, 450000000],    
    [902000000, 928000000]     
  ],
  "sweep_step": 1000000,
  "sweep_dwell_time": 0.5,
  "detection_thresholds": {
    "signal_threshold": -70,
    "min_hop_rate": 5,
    "max_dwell_time": 2.0,
    "active_probe_threshold": -40
  },
  "alerting": {
    "confidence_threshold": 0.7,
    "email_alerts": false,
    "log_level": "INFO"
  }
}
```

## Frequency Band Configuration

### Common Target Frequencies by Use Case

#### Public Safety & Emergency Services
- **VHF Low**: 30-50 MHz (Fire, EMS in some areas)
- **VHF High**: 144-174 MHz (Police, Fire, EMS)
- **UHF**: 450-470 MHz (Police, Fire, EMS)
- **700/800 MHz**: 700-800 MHz (Digital trunked systems)

#### Commercial Two-Way Radio
- **VHF**: 136-174 MHz (Business, marine)
- **UHF**: 400-470 MHz (Business, construction)
- **GMRS**: 462-467 MHz (General Mobile Radio Service)

#### Access Control & Remote Devices
- **315 MHz**: Garage doors, car remotes (US)
- **433 MHz**: Industrial remote controls (International)
- **902-928 MHz**: ISM band devices
- **2.4 GHz**: WiFi, Bluetooth, some remotes

#### Aviation
- **VHF**: 118-137 MHz (Air traffic control)
- **UHF**: 225-400 MHz (Military aviation)

## Usage Examples

### Basic Operation
```bash
# Start the detection system
python3 rf_scanner_detection.py

# View recent detections
python3 -c "
from rf_scanner_detection import RFScannerDetector
detector = RFScannerDetector()
detections = detector.get_recent_detections(hours=24)
for d in detections[-10:]:  # Last 10 detections
    print(f'{d.timestamp}: {d.detection_type} at {d.frequency/1e6:.3f} MHz (conf: {d.confidence:.2f})')
"
```

### Custom Frequency Monitoring
```python
# Monitor specific frequencies your client uses
custom_config = {
    "frequency_ranges": [
        [462000000, 467000000],  # GMRS band
        [154000000, 158000000]   # VHF business band
    ],
    "sweep_step": 25000,  # 25 kHz steps for narrow monitoring
    "sweep_dwell_time": 1.0  # Longer dwell for better detection
}
```

## Detection Types Explained

### 1. **Scanning Detection**
- **Trigger**: Rapid frequency hopping (>5 hops/second)
- **Confidence**: Based on hop rate and frequency spread
- **Use Case**: Detects radio scanners sweeping multiple channels

### 2. **Targeted Monitoring**
- **Trigger**: Sustained presence on specific frequency (>10 seconds)
- **Confidence**: Based on dwell time and signal consistency
- **Use Case**: Detects someone monitoring your specific channel

### 3. **Active Probe Detection**
- **Trigger**: Strong, brief transmissions (-40 dBm threshold)
- **Confidence**: Based on signal strength above threshold
- **Use Case**: Detects active RF probes or direction finding

### 4. **Passive Listening Detection**
- **Trigger**: Carrier sense patterns without transmission
- **Confidence**: Statistical analysis of receiver signatures
- **Use Case**: Detects passive monitoring devices

## Security Considerations

### Operational Security (OPSEC)
1. **Covert Operation**: System operates passively - no transmissions
2. **Log Security**: Encrypt detection database if storing sensitive data
3. **False Positives**: Tune thresholds to minimize legitimate traffic alerts
4. **Legal Compliance**: Ensure monitoring complies with local regulations

### Performance Optimization
```python
# High-sensitivity configuration for weak signals
high_sensitivity_config = {
    "gain": 40,
    "signal_threshold": -80,
    "sweep_dwell_time": 2.0
}

# Fast-sweep configuration for wide area monitoring
fast_sweep_config = {
    "sweep_step": 5000000,  # 5 MHz steps
    "sweep_dwell_time": 0.1,
    "frequency_ranges": [[30e6, 1000e6]]  # Very wide range
}
```

## Integration with Security Operations

### SIEM Integration Template
```python
def send_to_siem(detection):
    """Send detection to SIEM system"""
    siem_event = {
        "source": "RF_Scanner_Detection",
        "severity": "HIGH" if detection.confidence > 0.8 else "MEDIUM",
        "event_type": "RF_RECONNAISSANCE",
        "timestamp": detection.timestamp.isoformat(),
        "frequency_mhz": detection.frequency / 1e6,
        "detection_type": detection.detection_type,
        "confidence": detection.confidence,
        "metadata": detection.metadata
    }
    # Send to your SIEM API endpoint
    # requests.post('https://your-siem.com/api/events', json=siem_event)
```

### Alert Escalation
```python
def escalate_detection(detection):
    """Escalate high-confidence detections"""
    if detection.confidence > 0.9:
        # High confidence - immediate alert
        send_sms_alert(detection)
        send_email_alert(detection)
    elif detection.confidence > 0.7:
        # Medium confidence - log and email
        send_email_alert(detection)
    else:
        # Low confidence - log only
        logger.info(f"Low confidence detection: {detection}")
```

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
# Log out and back in
```

#### GNU Radio Errors
```bash
# Test GNU Radio installation
python3 -c "import gnuradio; print('GNU Radio OK')"
python3 -c "import osmosdr; print('OsmoSDR OK')"

# If gr-osmosdr missing:
sudo apt install gr-osmosdr  # Ubuntu/Debian
```

#### Performance Issues
- **High CPU Usage**: Reduce sample rate or FFT size
- **Memory Issues**: Implement circular buffers for long-running detection
- **Missed Detections**: Increase gain or lower signal threshold

### Validation Testing

#### Test with Known Scanner
1. Use a legitimate radio scanner near your detection system
2. Verify detection alerts are generated
3. Adjust sensitivity thresholds as needed

#### False Positive Testing
1. Monitor normal radio traffic in your area
2. Document legitimate signals being flagged
3. Tune detection algorithms to reduce false positives

## Advanced Features

### Machine Learning Enhancement
```python
# Optional: Add ML-based pattern recognition
from sklearn.ensemble import IsolationForest

class MLEnhancedDetector(RFScannerDetector):
    def __init__(self):
        super().__init__()
        self.anomaly_detector = IsolationForest(contamination=0.1)
        
    def enhance_detection_with_ml(self, features):
        # Extract features: hop_rate, dwell_time, signal_strength, etc.
        anomaly_score = self.anomaly_detector.decision_function([features])
        return anomaly_score[0]
```

### Multi-HackRF Setup
```python
# For covering multiple frequency ranges simultaneously
class MultiHackRFDetector:
    def __init__(self, device_ids=['0', '1']):
        self.devices = []
        for device_id in device_ids:
            hackrf = HackRFController(device_id=device_id)
            self.devices.append(hackrf)
```

This system provides comprehensive RF surveillance detection capabilities. Start with the basic configuration and adjust parameters based on your specific environment and threat model.