
from scapy.all import *

def tcp_throttling(source_addr: str, dest_addr: str, approach = "ACK"):

    #ERROR CHECK ADDRESSER
    print(f"dst host {dest_addr} and src host {source_addr}")

    sniffed_package = sniff(filter = f"tcp and dst host {dest_addr} and src host {source_addr}", count = 30)
    #sniffed_package = sniff(filter = f"tcp", count = 5)
    sniffed_package.summary()

    if approach == "ACK":
        pass
    elif approach == "RST":
        pass
    else:
        raise ValueError("Incorrect or invalid approach")


def main():
    
    tcp_throttling("192.168.0.116", "192.168.0.128", "ACK")
    

if __name__ == "__main__":
    main()

