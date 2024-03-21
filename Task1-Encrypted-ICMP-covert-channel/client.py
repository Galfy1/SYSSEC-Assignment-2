
import socket

def read_address():
    r = input("Enter the IP address of the server: ")
    print("The IP address of the server is: ", r)
    return r


def main():
    server_address = read_address()

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)



if __name__ == "__main__":
    main()