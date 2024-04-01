
import socket
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES

SERVER_ADRRESS = "localhost"
SERVER_PORT = 12345

SYMMETRIC_KEY =  bytes.fromhex("7f6aa21dfd3cf2c2cd7135f695cd3e04288703614fdb8bfc07c974d7845ed654") # Shared key
IPV4_PACKET_MAX_SIZE = 65535 # Bytes
AES_BLOCK_SIZE = 16 # Bytes
IP_HEAD_LEN_BYTE = 0 # Byte location in header
ICMP_HEADER_LEN = 8 # Bytes
IV_LEN = AES_BLOCK_SIZE # Bytes

def unpack_packet(packet):
    
    ip_header_len = (int(packet[:1].hex()[1], 16) * 32) // 8 # read IP header length from second nibble in ip header
        
    icmp_packet = packet[ip_header_len:]
    icmp_payload = icmp_packet[ICMP_HEADER_LEN:]
    iv = icmp_payload[:IV_LEN]
    ciphertext = icmp_payload[IV_LEN:]
    
    return iv, ciphertext 

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.bind((SERVER_ADRRESS, SERVER_PORT))
    print("Server is listening on port: ", SERVER_ADRRESS, SERVER_PORT, "\n")

    while True:
        recPacket, addr = s.recvfrom(IPV4_PACKET_MAX_SIZE)
        
        
        iv, ciphertext = unpack_packet(packet = recPacket)

        cipher = AES.new(SYMMETRIC_KEY, AES.MODE_CBC, iv)  # CBC AES is used for decryption
        plaintext = unpad(cipher.decrypt(ciphertext), AES_BLOCK_SIZE)

        print(f"Received message: {plaintext}")

if __name__ == "__main__":
    main()
