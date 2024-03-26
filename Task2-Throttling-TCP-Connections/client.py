import socket
import time

host = "188.177.168.187"
port = 12345

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect(((host, port)))
    time.sleep(2)
    s.sendall(b"davs")

if __name__ == "__main__":
    main()