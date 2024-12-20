from CovertChannelBase import CovertChannelBase
from scapy.layers.l2 import ARP, Ether
from scapy.all import sniff, get_if_list, conf
import time

class MyCovertChannel(CovertChannelBase):
    """
    Enhanced Covert Storage Channel implementation using ARP Destination MAC Address field.
    
    This implementation uses the last two bytes of the destination MAC address in ARP packets
    to encode binary data. Using a 2-bit encoding scheme:
    - 00:00 represents '00'
    - 00:FF represents '01'
    - FF:00 represents '10'
    - FF:FF represents '11'
    
    Channel Capacity: ~16.35 bits/second
    """
    
    def __init__(self):
        super().__init__()
        conf.verb = 0
    
    def encode_bits_to_mac(self, bits):
        """Helper function to encode 2 bits into a MAC address"""
        base_mac = "00:11:22:33:"  # First 4 bytes constant
        # Encode 2 bits using last two bytes
        if bits == "00":
            return base_mac + "00:00"
        elif bits == "01":
            return base_mac + "00:FF"
        elif bits == "10":
            return base_mac + "FF:00"
        else:  # "11"
            return base_mac + "FF:FF"
    
    def decode_mac_to_bits(self, mac):
        """Helper function to decode a MAC address into 2 bits"""
        last_two_bytes = mac.split(":")[-2:]
        byte5, byte6 = [int(b, 16) for b in last_two_bytes]
        
        if byte5 == 0 and byte6 == 0:
            return "00"
        elif byte5 == 0 and byte6 == 255:
            return "01"
        elif byte5 == 255 and byte6 == 0:
            return "10"
        else:  # byte5 == 255 and byte6 == 255
            return "11"
    
    def send(self, min_length, max_length, log_file_name, packet_delay):
        """Send covert message using enhanced ARP packets encoding"""
        message = self.generate_random_message(min_length, max_length)
        self.log_message(message, log_file_name)
        
        print(f"Sending message: {message}")
        binary_message = ''.join(format(ord(c), '08b') for c in message)
        print(f"Binary message: {binary_message}")
        
        start_time = time.time()
        
        # Send two bits at a time
        for i in range(0, len(binary_message), 2):
            bits = binary_message[i:i+2]
            if len(bits) == 1:  # Handle odd number of bits
                bits += "0"
                
            arp = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(
                op=1,
                hwsrc="02:42:ac:11:00:02",
                psrc="172.18.0.2",
                hwdst=self.encode_bits_to_mac(bits),
                pdst="172.18.0.3"
            )
            
            super().send(arp, interface="eth0")
            print(f"Sent bits: {bits}")
            time.sleep(packet_delay)
        
        end_time = time.time()
        duration = end_time - start_time
        capacity = len(binary_message) / duration
        print(f"Enhanced channel capacity: {capacity:.2f} bits/second")
    
    def receive(self, log_file_name, timeout):
        """Receive and decode covert message from enhanced ARP packets"""
        received_bits = []
        print(f"Starting enhanced receiver on eth0 (timeout: {timeout}s)")
        
        def packet_callback(packet):
            if ARP in packet:
                # Check if it's our covert channel packet
                if packet[ARP].hwdst.startswith("00:11:22:33"):
                    mac = packet[ARP].hwdst
                    bits = self.decode_mac_to_bits(mac)
                    received_bits.extend(list(bits))
                    print(f"Received bits: {bits} from MAC: {mac}")
        
        try:
            print("Waiting for packets...")
            sniff(
                iface="eth0",
                filter="arp",
                prn=packet_callback,
                timeout=timeout,
                store=0
            )
        except Exception as e:
            print(f"Error during capture: {e}")
        
        print(f"Capture complete. Received {len(received_bits)} bits")
        
        if not received_bits:
            print("No bits received")
            return
        
        # Convert bits to message
        bits = ''.join(received_bits)
        print(f"Received bits: {bits}")
        
        message = ''
        for i in range(0, len(bits), 8):
            byte = bits[i:i+8]
            if len(byte) == 8:
                message += chr(int(byte, 2))
        
        self.log_message(message, log_file_name)
        print(f" message: {message}")
