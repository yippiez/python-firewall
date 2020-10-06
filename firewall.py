"""
DONE: Block connections based on port
TODO: Check incoming ips rep
DONE: Syn flood attack protection
DONE: Dos protection
DONE: Log every suspicious packet to a pcap file
"""
import pydivert
from util.pydivertwriter import PydivertWriter
import threading
from time import sleep

port_list = list()      # Ports that firewall will block incoming connections
icmp_packets = dict()   # ip:count refreshes every REFRESH_RATE min
syn_packets = dict()    # ip:count refreshes every REFRESH_RATE min
REFRESH_RATE = 10
ICMP_PACKET_COUNT = 15  # max {icmp} packet allowed from a certain ip
SYN_PACKET_COUNT = 30   # max {syn}  packet allowed from a certain ip
log_file = PydivertWriter("firewall_log.pcap", sync=True, append=True)


def icmp_logic(w, packet):
    packet_ip = packet.src_addr
    print(f"DEBUG -> GOT A PING PACKET FROM {packet_ip}")
    # Adding packet to dict and adding to it
    if packet_ip in icmp_packets:
        icmp_packets[packet_ip] += 1
    else:
        icmp_packets[packet_ip] = 0
        icmp_packets[packet_ip] += 1
    # if max count has been reached disallow packet
    if icmp_packets[packet_ip] > ICMP_PACKET_COUNT:
        print(f"Too many ping requests from: {packet_ip} dropping packets")
        # This is here to prevent the pcap file getting too big
        if icmp_packets[packet_ip]-ICMP_PACKET_COUNT < 10:
            log_file.write(packet)
    else:
        w.send(packet)


def syn_logic(w, packet):
    packet_ip = packet.src_addr
    print(f"DEBUG -> GOT A SYN PACKET FROM {packet_ip}")
    # adding one to dict value if exist else create one then add
    if packet_ip in syn_packets:
        syn_packets[packet_ip] += 1
    else:
        syn_packets[packet_ip] = 0
        syn_packets[packet_ip] += 1
    # if max count has been reached disallow packet
    if syn_packets[packet_ip] > SYN_PACKET_COUNT:
        print(f"Too many syn requests from: {packet_ip} dropping packets")
        # This is here to prevent the pcap file getting too big
        if syn_packets[packet_ip] - SYN_PACKET_COUNT < 10:
            log_file.write(packet)
    else:
        w.send(packet)


def blacklist_check(ip):
    pass


# this is not the best way
def clear_loop():
    global icmp_packets
    global syn_packets
    global REFRESH_RATE

    while True:
        sleep(REFRESH_RATE * 60)
        icmp_packets = dict()
        syn_packets = dict()


threading.Thread(target=clear_loop).start()
with pydivert.WinDivert("tcp.Syn or icmp") as w:
    for packet in w:
        # skips if blacklisted port
        if packet.dst_port in port_list:
            continue
        elif packet.icmp:
            icmp_logic(w, packet)
        elif packet.tcp.syn:
            syn_logic(w, packet)
        else:
            w.send(packet)
