# COVERTOVERT - Covert Channel Implementation

## Overview
Implementation of a covert storage channel using ARP protocol's Destination MAC Address field manipulation (CSC-PSV-ARP-DMA). This project demonstrates both standard and enhanced methods of covert communication through protocol field manipulation.

## Covert Channel Capacity Measurement

### Methodology
1. Message size: 128 bits (16 characters)
2. Timer implementation:
   ```python
   start_time = time.time()
   # Send packets...
   end_time = time.time()
   duration = end_time - start_time
   capacity = 128 / duration  # bits per second
   ```

### Results
1. **Basic Implementation (1 bit/packet)**
   - Capacity: 8.18 bits/second
   - Calculation: 128 bits / 15.6 seconds
   - Limitation: One bit encoded per MAC address

2. **Enhanced Implementation (2 bits/packet)**
   - Capacity: 16.35 bits/second
   - Calculation: 128 bits / 7.8 seconds
   - Improvement: Two bits encoded per MAC address

### Capacity Maximization Techniques
1. **Dual-Byte Encoding**
   - Utilizes last two bytes of MAC address
   - Doubles information density per packet
   - Encoding scheme:
     ```
     00 → 00:11:22:33:00:00
     01 → 00:11:22:33:00:FF
     10 → 00:11:22:33:FF:00
     11 → 00:11:22:33:FF:FF
     ```

2. **Optimized Packet Delay**
   - Minimum delay (0.1s) to ensure reliability
   - Balance between speed and packet loss
   - Tested various delays to find optimal value

3. **Protocol Efficiency**
   - Uses broadcast ARP requests
   - Minimizes network overhead
   - Ensures reliable packet delivery

## Implementation Details

### Configuration Parameters
```json
{
    "covert_channel_code": "CSC-PSV-ARP-DMA",
    "send": {
        "min_length": 16,
        "max_length": 16,
        "log_file_name": "sender.log",
        "packet_delay": 0.1
    },
    "receive": {
        "log_file_name": "receiver.log",
        "timeout": 60
    }
}
```

### Limitations and Thresholds
1. **Network Constraints**
   - Minimum packet delay: 0.1s (required for network stability)
   - Maximum theoretical capacity: 20 bits/second
   - Network latency impact: ~5-10ms per packet

2. **Protocol Limitations**
   - ARP protocol overhead
   - MAC address format restrictions
   - Network segment requirements

3. **Implementation Bounds**
   - Fixed message length: 16 characters (128 bits)
   - Constant prefix requirement: 00:11:22:33
   - Error checking overhead

## Usage Instructions
1. Start receiver:
```bash
make receive
```

2. Start sender:
```bash
make send
```

3. Verify transmission:
```bash
make compare
```

## Technical Requirements
- Python 3.10.12
- Scapy library
- Docker environment
- Same network segment for sender/receiver

## Performance Analysis
The enhanced implementation achieves near-optimal performance given the constraints:
1. Network delay minimum (0.1s) cannot be reduced without packet loss
2. Protocol overhead is minimized
3. Maximum bits per packet (2) while maintaining protocol compliance
4. Theoretical maximum (~20 bits/second) vs. Achieved (16.35 bits/second)
5. 81.75% efficiency of theoretical maximum capacity

The implementation successfully maximizes covert channel capacity through:
- Optimal packet timing
- Maximum bit encoding density
- Efficient protocol usage
- Reliable transmission methods
