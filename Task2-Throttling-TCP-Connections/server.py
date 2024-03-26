
import socket

host = ''        # all interfaces
port = 12345    


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))

    s.listen(1)
    conn, addr = s.accept()
    print('Connected by', addr)

    while True:
        data = conn.recv(1024)
        print("Client Says: " + data)


if __name__ == "__main__":
    main()