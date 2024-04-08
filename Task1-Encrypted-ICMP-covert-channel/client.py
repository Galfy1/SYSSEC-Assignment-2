
import socket
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import secrets

SYMMETRIC_KEY =  bytes.fromhex("7f6aa21dfd3cf2c2cd7135f695cd3e04288703614fdb8bfc07c974d7845ed654") # Shared key
ICMP_HEADER_LEN = 8 # Bytes
ICMP_PAYLOAD_MAX_SIZE = 576 - ICMP_HEADER_LEN # Bytes
AES_BLOCK_SIZE = 16 # Bytes

def read_address():
    addr = input("Enter the IP address of the server: ") or "localhost"
    print("The IP address of the server is: ", addr)
    port = input("Enter the port number of the server: ") or "12345"
    print("The port number of the server is: ", port)

    return addr, port

def create_icmp_header(icmp_type = b"\x2F", icmp_code = b"\x00", icmp_checksum = b"\x00\x00", icmp_rest_of_header = b"\x00\x00\x00\x00"):

    # ICMP type is set to 47 in decimal numbers.
    # ICMP code is set to 0 in decimal numbers - Field omitted.
    # ICMP checksum is set to 0 in decimal numbers - Field omitted.
    # ICMP rest of header field set to 0 in decimal - Field omitted.

    icmp_header = icmp_type + icmp_code + icmp_checksum + icmp_rest_of_header

    return icmp_header

def encrypt_n_send(data: bytes, dest_addr, dport, socket: socket):

    
    iv = secrets.token_bytes(AES_BLOCK_SIZE) # Generating a cryptograhical secure IV.
    data_padded = pad(data, AES_BLOCK_SIZE)
    
    if (len(data_padded) + len(iv)) > ICMP_PAYLOAD_MAX_SIZE:
        raise ValueError(f"ICMP payload size to large at {len(icmp_packet)} bytes!")

    cipher = AES.new(SYMMETRIC_KEY, AES.MODE_CBC, iv)  # CBC AES is used for encryption
    ciphertext = cipher.encrypt(data_padded)

    icmp_packet = create_icmp_header() + iv + ciphertext

    socket.sendto(icmp_packet, (dest_addr, dport)) 


def main():

    dest_addr, dport = read_address()
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    
    while True:
        data = input("Enter your message: ")
        encrypt_n_send(data.encode('utf-8'), dest_addr, int(dport), s)
        print("Message sent!")
        
if __name__ == "__main__":
    main()