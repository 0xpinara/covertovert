from CovertChannelBase import CovertChannelBase
from scapy.layers.l2 import ARP, Ether
from scapy.all import sniff, get_if_list, conf
import random
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
    
    a = 1
    b = 1
    c = 1
    stop_rec = False

    def __init__(self):
        super().__init__()
        conf.verb = 0
    
    def encode_bits_to_mac(self, bits):

        shift = self.c*(self.a + self.b) % 24
        print(f"Shift: {shift}")
        self.b = self.a + self.b
        self.a = self.b - self.a
        self.c = self.c + 1

        secret_message_shush = []
        for bit in bits:
            other_bit = '0' if bit == '1' else '1'
            truple = [other_bit, other_bit, other_bit]
            zero_or_two = random.choice([0, 2])
            if zero_or_two == 2:
                place = random.choice([0, 1, 2])
                truple = [bit, bit, bit]
                truple[place] = other_bit
            secret_message_shush.extend(truple)

        secret_string = ''.join(secret_message_shush)
        shifted_secret_string = secret_string[-shift:] + secret_string[:-shift]

        encoded_mac = ""
        bits48 = []
        signature = "011000010110100101101110"
        
        shifted_signature = signature[shift:] + signature[:shift]
        for j in range(24):
            bits48.append(shifted_signature[j])
            bits48.append(shifted_secret_string[j])
        for i in range(0, 48, 8):
            byte = int("".join(bits48[i:i+8]), 2)
            encoded_mac += f"{byte:02x}:"
        print(f"Encoded MAC: {encoded_mac[:-1]}")
        return encoded_mac[:-1]

    
    def decode_mac_to_bits(self, bit_v):
        shift = (self.c-1)*(self.b) % 24
        decodee = []

        for i in range(24):
            decodee.append(bit_v[(i*2)+1])
        
        garbled_message = ''.join(decodee)
        shifted_message = garbled_message[shift:] + garbled_message[:shift]

        bits = []

        for j in range(8):
            ones = 0
            zeros = 0
            if shifted_message[j*3] == '1':
                ones += 1
            else:
                zeros += 1
            if shifted_message[(j*3)+1] == '1':
                ones += 1
            else:
                zeros += 1
            if shifted_message[(j*3)+2] == '1':
                ones += 1
            else:
                zeros += 1
            if zeros % 2 == 1:
                bits.append('1')
            else:
                bits.append('0')

        if("".join(bits) == "00101110"):
            self.stop_rec = True            

        return bits

    
    def send(self, min_length, max_length, log_file_name, packet_delay):
        """Send covert message using enhanced ARP packets encoding"""
        message = self.generate_random_message(min_length, max_length)
        message = "Present day, present time" + "."
        self.log_message(message, log_file_name)
        
        print(f"Sending message: {message}")
        binary_message = ''.join(format(ord(c), '08b') for c in message)
        print(f"Binary message: {binary_message}")
        
        start_time = time.time()
        
        # Send 8 bits at a time
        for i in range(0, len(binary_message), 8):
            bits = binary_message[i:i+8]
                
            arp = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(
                op=1,
                hwsrc="02:42:ac:11:0a0:02",
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
        
        def check_ain(bit_v):
            shift = self.c*(self.a + self.b) % 24
            bits = []
            for i in range(0, len(bit_v), 2):
                bits.append(bit_v[i])
            signature = "011000010110100101101110"
            if "".join(bits) == signature[shift:] + signature[:shift]:
                self.b = self.a + self.b
                self.a = self.b - self.a
                self.c = self.c + 1
                return True
            return False

        def packet_callback(packet):
            if ARP in packet:
                mac = packet[ARP].hwdst
                mac = mac.replace(":", "")
                bit_v = []
                for he in mac:
                    bin = format(int(he, 16), '04b')
                    bit_v.append(bin[0])
                    bit_v.append(bin[1])
                    bit_v.append(bin[2])
                    bit_v.append(bin[3])
                if check_ain(bit_v):                    
                    bits = self.decode_mac_to_bits(bit_v)
                    received_bits.extend(bits)
                    print(f"Received bits: {bits} from MAC: {packet[ARP].hwdst}")


        try:
            print("Waiting for packets...")
            sniff(
                iface="eth0",
                filter="arp",
                prn=packet_callback,
                timeout=timeout,
                store=0,
                stop_filter=lambda p: self.stop_rec
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
