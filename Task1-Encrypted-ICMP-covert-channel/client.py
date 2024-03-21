
import socket

ICMP_TYPE = 47

def read_address():
    addr = input("Enter the IP address of the server: ") or "localhost"
    print("The IP address of the server is: ", addr)
    port = input("Enter the port number of the server: ") or "12345"
    print("The port number of the server is: ", port)

    return addr, port


def main():
    #server_address, port = read_address()
    print("hello world")

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    #s.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
    #s.connect((server_address, int(port)))
    #s.sendall(b"Hello, world")
    #s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    packet = b'\x47\x00\x00\x00\x69\x69\x69\x69\x69\x69\x69\x69\x69'  # ICMP HEADER + DATA (FULL HEADER IS REQUIRED)
    s.sendto(packet, ("localhost", 700))  # 700 is just a random port



if __name__ == "__main__":
    main()