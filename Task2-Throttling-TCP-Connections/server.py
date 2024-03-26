
import socket

host = ""        # all interfaces
port = 12345    


def main():

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))

    s.listen(1)
    conn, addr = s.accept()
    print('Connected by', addr)

    while True:
        data = conn.recv(1024)
        if not data: break
        print("Client Says: " + data.decode('utf-8'))



if __name__ == "__main__":
    main()