from CovertChannelBase import CovertChannelBase
from scapy.layers.l2 import ARP, Ether
from scapy.all import sniff, get_if_list, conf
import random
import time

class MyCovertChannel(CovertChannelBase):
    """
    Enhanced Covert Storage Channel implementation using ARP Destination MAC Address field.
    
    This implementation uses 24 bits of the ARP Destination MAC Address field to encode 8 bits of data, and the 24 other bits to encode a signature.
    
    Signature is 011000010110100101101110 which means "ain" in 8-bit ASCII. (the word "ain" comes from the protoganists
    of the anime "Serial Experiments Lain" and the story "Despera", whose names are Lain Iwakura and Ain respectively).
    This signature is first shifted by i*(fibonacci(i+2))%24 bits, where i is the index of the message being sent, starting from 1.
    After this, the signature is written to the 1st, 3rd, 5th ... 47th bits of the MAC address to increase randomness in the mac adress.

    Then an 8 bit message is encoded in the remaining bits of the MAC address. For every bit, 3 bits are written to the MAC address.
    Since in 3 is an odd number and has to be the sum of an even and odd number(0+3, 1+2), the hidden bit is the bit that is present in the 3 bits in an even amount.
    For example: 000 encodes 1 since amount of 1 is even(0), 101 also encodes 1 since amount of 1 is even(2).
    I choose a random number between 0 or 2 for the amount of the hidden bit. If it is 0 then I just fill the three bits with the counterpart of the bit I want to encode.
    If it is 2, then I choose a random place to put the counterpart of the bit and fill the rest with the hidden bit I want to encode. 
    Then I shift the message by -i*(fibonacci(i+1))%24 bits and write it into the 2nd, 4th, 6th ... 48th bits of the MAC address.

    The receiver start from i=1 for the shift amount and checks if the signature is correct. If it is correct, then it decodes the message and increases i by 1.
    
    In the code, variables a and b are used to calculate fibonacci numbers. The c is used to calculate the index.

    Channel Capacity: ~67 bits/second
    """
    
    a = 1
    b = 1
    c = 1 
    stop_rec = False

    def __init__(self):
        super().__init__()
        conf.verb = 0
    
    def encode_bits_to_mac(self, bits):

        # Calculate shift amount
        shift = self.c*(self.a + self.b) % 24
        self.b = self.a + self.b
        self.a = self.b - self.a
        self.c = self.c + 1

        secret_message_shush = []
        for bit in bits:
            other_bit = '0' if bit == '1' else '1'
            truple = [other_bit, other_bit, other_bit] # Fill the 3 bits with the counterpart of the bit
            zero_or_two = random.choice([0, 2]) # Choose 0 or 2 for the amount of the hidden bit
            if zero_or_two == 2: # If it is 0, do nothing truple will be the same. If it is 2, choose a random place to put the counterpart of the bit
                place = random.choice([0, 1, 2])
                truple = [bit, bit, bit]
                truple[place] = other_bit
            secret_message_shush.extend(truple)

        secret_string = ''.join(secret_message_shush)
        shifted_secret_string = secret_string[-shift:] + secret_string[:-shift] # Shift the message by -i*(fibonacci(i+2))%24 bits

        encoded_mac = "" # Will be the encoded MAC address
        bits48 = [] # Will be the 48 bits of the MAC address
        signature = "011000010110100101101110" # ain        
        shifted_signature = signature[shift:] + signature[:shift] # Shift the signature by i*(fibonacci(i+2))%24 bits

        for j in range(24): # Encode signature and secret message to the MAC address one by one
            bits48.append(shifted_signature[j])
            bits48.append(shifted_secret_string[j])

        for i in range(0, 48, 8): # Convert to hexadecimal with : symbols for MAC address
            byte = int("".join(bits48[i:i+8]), 2)
            encoded_mac += f"{byte:02x}:"

        return encoded_mac[:-1] # Remove the last : symbol and send the MAC address

    
    def decode_mac_to_bits(self, bit_v): # We call this function when we are sure that the signature is correct
        shift = (self.c-1)*(self.b) % 24 # Calculate the shift amount
        decodee = []

        for i in range(24): # Get the secret message from the MAC address
            decodee.append(bit_v[(i*2)+1])
        
        garbled_message = ''.join(decodee)
        shifted_message = garbled_message[shift:] + garbled_message[:shift] # Unshift the message

        bits = [] # Will be the decoded bits

        for j in range(8): # Count the bits in every 3 bits and decide the hidden bit
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
            if zeros % 2 == 1: # If it has odd amount of zeros, then the hidden bit is 1
                bits.append('1')
            else:
                bits.append('0')

        if("".join(bits) == "00101110"): # If the message is ".", then stop the receiver
            self.stop_rec = True            

        return bits

    
    def send(self, min_length, max_length, log_file_name, packet_delay):
        """Send covert message using enhanced ARP packets encoding"""
        message = self.generate_random_message(min_length, max_length)
        self.log_message(message, log_file_name)
        
        binary_message = ''.join(format(ord(c), '08b') for c in message)
        
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
        
        def check_ain(bit_v): # Check if the signature is correct
            shift = self.c*(self.a + self.b) % 24 # Calculate the shift amount
            bits = [] # Will be the bits of the signature
            for i in range(0, len(bit_v), 2): # Get the bits of the signature from the MAC address
                bits.append(bit_v[i])
            signature = "011000010110100101101110" 
            if "".join(bits) == signature[shift:] + signature[:shift]: # Check if the signature is correct
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
                for he in mac: # Get the bits of the MAC address for ease of use
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
                stop_filter=lambda p: self.stop_rec # Stop the receiver if the message is "."
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
