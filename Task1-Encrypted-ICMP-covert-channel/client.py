
import socket
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import secrets

CLIENT_ADDRESS = "localhost"
CLIENT_PORT = 12345

SYMMETRIC_KEY =  bytes.fromhex("7f6aa21dfd3cf2c2cd7135f695cd3e04288703614fdb8bfc07c974d7845ed654") # Shared key
ICMP_PAYLOAD_MAX_SIZE = 65507 # Bytes
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

def encrypt_n_send(data: bytes, socket: socket):

    
    iv = secrets.token_bytes(AES_BLOCK_SIZE) # Generating a cryptograhical secure IV.
    data_padded = pad(data, AES_BLOCK_SIZE)
    
    if (len(data_padded) + len(iv)) > ICMP_PAYLOAD_MAX_SIZE:
        raise ValueError(f"ICMP payload size to large at {len(icmp_packet)} bytes!")

    cipher1 = AES.new(SYMMETRIC_KEY, AES.MODE_CBC, iv)  # CBC AES is used for encryption
    ciphertext = cipher1.encrypt(data_padded)

    icmp_packet = create_icmp_header() + iv + ciphertext

    socket.sendto(icmp_packet, (CLIENT_ADDRESS, CLIENT_PORT)) 


def main():
    #server_address, port = read_address()

    #s.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
    #s.connect((server_address, int(port)))
    #s.sendall(b"Hello, world")
    #s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    #packet = b'\x47\x00\x00\x00\x69\x69\x69\x69\x69\x69\x69\x69\x69'  # ICMP HEADER + DATA (FULL HEADER IS REQUIRED)
    
    
    #print(f"IMCP header: {icmp_header}")
    
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    encrypt_n_send("Lets gOOOOOOO :D".encode('utf-8'), s)
    
    



    
if __name__ == "__main__":
    main()