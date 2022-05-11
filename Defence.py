from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
import AP_Handler as aph

W = '\033[0m'  # white
R = '\033[31m'  # red
B = '\033[34m'  # blue
P = '\033[35m'  # purple

ESSID = 0  # Ap's name
BSSID = 1  # Ap's mac address
CHANNEL = 2  # Ap's channel
search_time = 60
counter = 0
dup_APs_list = []  # [essid, bssid, channel]
essids_set = set()


def deauth_detector(interface, ap, flag=False):
    global ap_mac
    ap_mac = ap[BSSID]
    if not flag:
        print(P + "*** Step 3: Sniffing the packets and checking for attack. *** \n" + W)
        print(
            P + "In case that will be sniffed 30 deauthentication packets, you will alerted that there is attempt to "
                "do "
                "deathentication attack to the AP you choose. \n" + W)
        input(B + "Press Enter to continue.........\n" + W)
    # Sniffing packets - searching for deauthentication packets that are sending to the choosen AP
    sniff(iface=interface, prn=check_packet, timeout=search_time)
    if counter == 30:
        print(R + "WARNING!! your network in attack \n" + W)
        input(B + "Press enter to start protecting..... \n" + W)
        return True
    else:
        choice = input(B + "No Attack detected, keep scanning? Y/n" + W)
        if choice == "Y" or choice == "y":
            deauth_detector(interface=interface, ap=ap, flag=True)
        else:
            return False


def check_packet(pkt):
    # If we capture deauthentication packet
    # Deauthentication frame is management frame (type 0) and subtype 12 (0xC)
    # Management frames are used by IEEE 802.11 to permit a wireless client to negotiate with a Wireless Access Point
    global counter
    if pkt.type == 0 and pkt.subtype == 0xC:
        try:
            # If we capture deauthentication packet that intended to the choosen AP
            if ap_mac in str(pkt.addr2):
                counter += 1
                print(R + "Deauthentication packet has been sniffed. Packet number: " + str(counter) + W)
        except:
            print("Failed sniff packets")


def change_channel(interface):
    channel_switch = 1
    while True:
        try:
            if os.system('iwconfig %s channel %d' % (interface, channel_switch)) != 0:
                raise Exception()
            # switch channel in range [1,14] each 0.5 seconds
            channel_switch = channel_switch % 14 + 1
            time.sleep(0.5)
        except:
            sys.exit(R + "can't switch channels at " + interface + W)


def packet_handler(packet):
    # We are interested only in Beacon frame
    # Beacon frames are transmitted periodically, they serve to announce the presence of a wireless LAN
    if packet.haslayer(Dot11Beacon):
        # Get the source MAC address - BSSID of the AP
        bssid = packet[Dot11].addr2
        # Get the ESSID (name) of the AP
        essid = packet[Dot11Elt].info.decode()
        # Check if the new found AP is with the same name of our AP
        if essid == ap_name:
            essids_set.add(essid)
            # network_stats() function extracts some useful information from the network - such as the channel
            stats = packet[Dot11Beacon].network_stats()
            # Get the channel of the AP
            channel = stats.get("channel")
            # Add the new found AP to the AP list
            dup_APs_list.append([essid, bssid, channel])


# After the user choose the AP he want to attack, we want to set the interface's channel to the same channel as the choosen AP.
def set_channel(channel, interface):
    if os.system('iwconfig %s channel %d' % (interface, channel)) != 0:
        sys.exit(R + "can't switch between channels" + W)


def APs_scan_duplications(interface, ap):
    print(P + "*** Step 4:  Find duplicate network's. *** \n" + W)
    input(B + "Press Enter to continue........." + W)
    channel_changer = threading.Thread(target=change_channel, args=(interface,))
    channel_changer.daemon = True
    channel_changer.start()
    print(P + "\n Scanning for networks...\n" + W)
    # Sniffing packets - scanning the network for AP in the area
    # iface – the interface that is in monitor mode
    # prn – function to apply to each packet
    # timeout – stop sniffing after a given time
    global ap_name
    ap_name = ap[ESSID]
    sniff(iface=interface, prn=packet_handler, timeout=search_time)
    num_of_APs = len(dup_APs_list)
    # If at least one AP was found, print all the found APs
    if num_of_APs > 0:
        # If at least 1 AP was found.
        print(P + "\n*************** Duplicate APs Table ***************\n" + W)
        for x in range(num_of_APs):
            print("[" + str(x) + "] - BSSID: " + dup_APs_list[x][BSSID] + " \t Channel:" + str(
                dup_APs_list[x][CHANNEL]) + " \t AP name: " + dup_APs_list[x][ESSID])
        print(P + "\n************* FINISH SCANNING *************\n" + W)
        # Choosing the AP to attack
        ap_index = int(input(B + "Please enter the number of the AP you want to attack: " + W))
        # Print the choosen AP
        print(P + "You choose the AP: [" + str(ap_index) + "] - BSSID: " + dup_APs_list[ap_index][
            BSSID] + " Channel:" + str(
            dup_APs_list[ap_index][CHANNEL]) + " AP name: " + dup_APs_list[ap_index][ESSID] + W)
        # Set the channel as the choosen AP channel in order to send packets to connected devices later
        set_channel(int(dup_APs_list[ap_index][CHANNEL]), interface)
        return dup_APs_list[ap_index]
    else:
        # If no AP was found.
        rescan = input(B + "No duplicate networks were found. Do you want to rescan? [Y/n] " + W)
        if rescan == "n":
            print(R + "  Bye  " + W)
            aph.deactivate_monitor(interface)
            sys.exit(0)
        else:
            APs_scan_duplications(interface, ap)
