
import socket
import struct

SERVER_ADRRESS = "localhost"
SERVER_PORT = 700



def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.bind((SERVER_ADRRESS, SERVER_PORT))
    print("Server is listening on port: ", SERVER_ADRRESS, SERVER_PORT, "\n")

    while True:
        recPacket, addr = s.recvfrom(1024)
        print("Packet received from: ", addr, "\n")
        print("Packet: ", recPacket, "\n")

if __name__ == "__main__":
    main()
