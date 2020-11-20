# region imports:
from time import sleep

from python_arptable import get_arp_table
from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import ARP, Ether

# endregion

ARP_REPLAY = 2
REFRESH_TIME = 10
# the lists that the detection tools will save the suspicious pair of ip+mac
option1_suspicious_lst = []
option2_suspicious_lst = []


# region detect with ARP:
def get_mac(ip: str) -> str:
    """
    Returns the MAC address of given ip

    :param ip: the ip addr
    :type ip: str
    :raises IndexError: if it is unable to find the mac for some reason
    :return: matches mac addr
    :rtype: str
    """
    p = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip)
    result = srp(p, timeout=3, verbose=False)[0]
    return result[0][1].hwsrc


def process(pkt):
    """
    get an ARP replay packet and check if it an fake replay or not
    if it fake - add it to the suspicious list

    :param pkt: the suspicious ARP replay packet
    :type pkt: scapy.layers.l2.Ether
    """
    try:
        real_mac = get_mac(pkt[ARP].psrc)
    except IndexError:
        print(f"Unable to find the real mac of {pkt[ARP].psrc}")
        print("It's may be a fake IP or firewall is blocking packets")
    else:
        # extract the MAC addr from the packet sent to us
        response_mac = pkt[ARP].hwsrc
        # if they're different, definitely there is an attack
        # and if the pair not in the suspicious list - add it
        if real_mac != response_mac:
            if (pkt[ARP].psrc, response_mac) not in option1_suspicious_lst:
                option1_suspicious_lst.append((pkt[ARP].psrc, response_mac))


def is_arp_replay(pkt):
    """
    check if the given packet is arp replay

    :param pkt: the packet to check
    :type pkt: scapy layer 2 packet
    :return: if it's arp replay
    :rtype: bool
    """
    return ARP in pkt and pkt[ARP].op == ARP_REPLAY


def detection_option1():
    """
    option 1 for detect a ARP Spoof attack
    we sending to each mac address in arp table arp request, expecting 2 answers:
    arp-spoof script and real machine response
    """
    sniff(store=False, lfilter=is_arp_replay, prn=process)


# endregion

# region detect with ICMP echo-request:

def check_arp_table():
    """
    option 2 for detect a ARP Spoof attack
    we sending each row an ping request with the arp table data
    """
    arp_table = get_arp_table()
    for i, row in enumerate(arp_table):
        ip = row['IP address']
        mac = row['HW address']
        ans = srp1(
            Ether(src=get_if_hwaddr(row['Device']), dst=mac) / IP(dst=ip) / ICMP(),
            timeout=5, verbose=False)
        if ans is None and (ip, mac) not in option2_suspicious_lst:
            option2_suspicious_lst.append((ip, mac))


def detection_option2():
    """
    option 2 for detect a ARP Spoof attack:
    for each pair of ip addr + mac addr in the machine's arp table,
    we send a echo request (= ICMP[type]=8) and wait for answer.
    if after 5 seconds there is no answer - add the suspicious pair to the list
    """
    while True:
        check_arp_table()
        sleep(REFRESH_TIME)


# endregion


def block_from_arp_table(ip: str, mac: str):
    """
    we blocking in arp tables the param ip and mac, working only on linux as root

    :param ip: ip to block
    :type ip: str
    :param mac: mac to block
    :type mac: str
    """
    subprocess.call(['arptables', '-A', 'INPUT', '-s', ip, '--source-mac', mac, '-j', 'DROP'])


def thwart_arp_spoof():
    """
    start in separate threads the two ARP spoof detection tools,
    if both tools suspicious in same pairs of ip+mac that in both lists -
    block the pair from the machine's arp table.
    """
    detect1 = threading.Thread(target=detection_option1)
    detect2 = threading.Thread(target=detection_option2)
    detect1.start()
    detect2.start()

    while True:
        imposter_pair = [pair for pair in option1_suspicious_lst if pair in option2_suspicious_lst]
        for pair in imposter_pair:
            print(f"[!] You are under attack, FAKE-MAC: {pair[1]} IMPOSTER-TO: {pair[0]}")
            block_from_arp_table(pair[0], pair[1])
            print("[!] The imposter had been removed from your arp table!")
            sleep(5)


if __name__ == '__main__':
    thwart_arp_spoof()