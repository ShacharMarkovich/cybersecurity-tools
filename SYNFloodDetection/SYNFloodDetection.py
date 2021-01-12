# Shachar markovich
from collections import Counter

from scapy.all import *

SYN = 'S'
RST = 'R'


def get_SYN_flood_ip(pcap_file_name: str, times: int):
    """
    Yield return all the IP addresses which send more than `times` TCP SYN segment and not send ANY other TCP packets.

    :param pcap_file_name: pcap file name which contains all the sniffed packets.
    :param times: the suspicious amount bar of sending only TCP SYN segments.
    :return: IP address and count of TCP SYN segments that it sent.
    """
    syn_count = Counter()  # TCP SYN segment counter
    not_syn_src_ips = []  # list of all ips that sent TCP packets that not part of the TCP 3-way handshake

    for pkt in rdpcap(pcap_file_name):
        if TCP in pkt and pkt[TCP].flags == SYN:  # if it TCP SYN segment...
            src = pkt.sprintf('{IP:%IP.src%}{IPv6:%IPv6.src%}')  # ... get IPv4 or IPv6 source address...
            syn_count[src] += 1  # ... and count the times that it send a TCP SYN segment

        if TCP in pkt and SYN not in pkt[TCP].flags:  # if it TCP packets that not part of the TCP 3-way handshake...
            src = pkt.sprintf('{IP:%IP.src%}{IPv6:%IPv6.src%}')  # ... get IPv4 or IPv6 source address...
            # .. and add the TCP segment sender's ip to list iff it not already in it
            if src not in not_syn_src_ips:
                not_syn_src_ips.append(src)

    # for each suspicious ip that send a TCP SYN segment check if it pass the suspicious conditions:
    for suspicious_ip in syn_count:
        if suspicious_ip not in not_syn_src_ips and syn_count[suspicious_ip] > times:
            yield suspicious_ip, syn_count[suspicious_ip]  # if yes - yield it


def SYN_flood_detection(pcap_file_name: str, appear: int):
    """
    Detect SYN Flood attack.
    Do it by find all IP addresses that send more than `appear` time a TCP SYN segment,
    and DIDN'T send any other kind of TCP segment.
    
    :param pcap_file_name: pcap file name which contains all the sniffed packets.
    :param appear: the suspicious amount bar of sending only TCP SYN segments.
    :return: IP address and count of TCP SYN segments that it sent.
    """
    count = 0
    for ip, times in get_SYN_flood_ip(pcap_file_name, appear):
        print("[!]", ip, "send TCP SYN segment", times,
              "times!\n\tHe didn't sent any more TCP packets! He is probably part from a SYN Flood Attack!")
        count += 1
    print('\n[!] There are in total', count, "different ips which appear more than", appear, 'times')


if __name__ == "__main__":
    SYN_flood_detection("SynFloodSample.pcap", 3)
