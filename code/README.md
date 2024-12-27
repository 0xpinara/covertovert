# COVERTOVERT - Covert Channel Implementation

## Overview
This project implements a covert storage channel using ARP protocol's Destination MAC Address field manipulation (CSC-PSV-ARP-DMA). We've developed an approach that combines dynamic shifting, error correction, and stealth techniques to create a reliable and undetectable covert channel.

## How It Works

### MAC Address Encoding
Our implementation uses three innovative techniques:

1. **Dynamic Shifting using Fibonacci Sequence**
   - Uses a shift value = (c * (a + b)) % 24
   - Shifts both signature and payload dynamically
   - Makes pattern detection extremely difficult
   - Shift changes with each packet based on Fibonacci numbers

2. **Triple Redundancy with Random Noise**
   ```python
   # Each bit is encoded into three bits with random noise
   bit '1' → [1,1,1] → randomly flip one bit: [1,0,1]
   bit '0' → [0,0,0] → randomly flip one bit: [0,1,0]
   ```
   This provides both error correction and enhanced stealth.

3. **Signature-Based Verification**
   - Embeds "ain" signature in binary
   - Signature shifts dynamically with Fibonacci sequence
   - Ensures packet authenticity
   - Helps receiver identify valid covert packets

## Performance

### Channel Capacity
Following the required measurement process:
1. Test message: 128 bits (16 characters)
2. Measured time: 1.896 seconds
3. Calculated capacity: 67.50 bits/second

This represents a significant improvement over basic implementations while maintaining stealth.

## Implementation Details

### Configuration Parameters
```json
{
    "covert_channel_code": "CSC-PSV-ARP-DMA",
    "send": {
        "min_length": 16,
        "max_length": 16,
        "log_file_name": "sender_log.txt",
        "packet_delay": 0.2
    },
    "receive": {
        "log_file_name": "receiver_log.txt",
        "timeout": 60
    }
}
```

### Limitations and Requirements
- Minimum packet delay: 0.2s (required for reliable transmission)
- Fixed message length: 16 characters
- Receiver timeout: 60 seconds
- Python 3.10.12
- Scapy library
- Docker environment

## Usage

1. Start the receiver first:
```bash
make receive
```

2. Then start the sender:
```bash
make send
```

3. Verify the transmission:
```bash
make compare
```

## Why This Implementation is Effective

1. **Stealth**
   - Dynamic shifting prevents pattern recognition
   - Random noise injection masks the encoding
   - Legitimate-looking ARP traffic

2. **Reliability**
   - Triple redundancy with error correction
   - Signature verification ensures authenticity
   - Robust against network interference

3. **Performance**
   - 67.50 bits/second throughput
   - Balanced speed and stealth
   - Reliable message delivery

This implementation successfully combines stealth, reliability, and performance while following all protocol and assignment requirements.
