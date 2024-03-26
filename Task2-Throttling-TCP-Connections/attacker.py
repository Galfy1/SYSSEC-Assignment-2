
from scapy.sendrecv import *

def tcp_throttling(source_addr, dest_addr, approach = "ACK"):

    sniffed_package = sniff(count = 20)
    sniffed_package[1].show()

    if approach == "ACK":
        pass
    elif approach == "RST":
        pass
    else:
        raise ValueError("Incorrect or invalid approach")


def main():
    tcp_throttling(12312312,123123,"ACK")
    

if __name__ == "__main__":
    main()

