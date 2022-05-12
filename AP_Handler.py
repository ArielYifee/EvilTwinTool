from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt

W = '\033[0m'  # white
R = '\033[31m'  # red
B = '\033[34m'  # blue
P = '\033[35m'  # purple

APs_list = []  # [essid, bssid, channel]
users_list = []
essids_set = set()
ESSID = 0  # Ap's name
BSSID = 1  # Ap's mac address
CHANNEL = 2  # Ap's channel
search_time = 60


def change_channel(interface):
    channel_switch = 1
    while True:
        try:
            if os.system('iwconfig %s channel %d' % (interface, channel_switch)) != 0:
                raise Exception()
            # switch channel in range [1,14] every 0.5 second.
            channel_switch = channel_switch % 14 + 1
            time.sleep(0.5)
        except:
            sys.exit(R + "can't switch channels at " + interface + W)


def packet_handler(packet):
    # We are interested only in Beacon frames.
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


#  After the user chooses the AP he wants to attack, we'll set the interface's channel to the same channel as the choosen AP.
def set_channel(channel, interface):
    if os.system('iwconfig %s channel %d' % (interface, channel)) != 0:
        sys.exit(R + "can't switch between channels" + W)


def APs_scanner(interface, flag=0):
    if flag == 0:
        print(P + "*** Step 2:  Choosing an network to attack. *** \n" + W)
    else:
        print(P + "*** Step 2:  Choosing an network to defence. *** \n" + W)
    input(B + "Press Enter to continue........." + W)
    channel_changer = threading.Thread(target=change_channel, args=(interface,))
    channel_changer.daemon = True
    channel_changer.start()
    print(P + "\n Scanning for networks...\n" + W)
    # Sniffing packets - scanning the network for AP in the area
    # iface – the interface that is in monitor mode
    # prn – function to apply to each packet
    # timeout – stop sniffing after a given time
    sniff(iface=interface, prn=packet_handler, timeout=search_time)
    num_of_APs = len(APs_list)
    # If at least one AP was found, print all the found APs
    if num_of_APs > 0:
        # If at least 1 AP was found.
        print(P + "\n*************** APs Table ***************\n" + W)
        for x in range(num_of_APs):
            print("[" + str(x) + "] - BSSID: " + APs_list[x][BSSID] + " \t Channel:" + str(
                APs_list[x][CHANNEL]) + " \t AP name: " + APs_list[x][ESSID])
        print(P + "\n************* FINISH SCANNING *************\n" + W)
        # Choosing the AP to attack
        if flag == 0:
            ap_index = int(input(B + "Please enter the number of the AP you want to attack: " + W))
        else:
            ap_index = int(input(B + "Please enter the number of the AP you want to defence: " + W))
        # Print the choosen AP
        print(P + "You choose the AP: [" + str(ap_index) + "] - BSSID: " + APs_list[ap_index][
            BSSID] + " Channel:" + str(
            APs_list[ap_index][CHANNEL]) + " AP name: " + APs_list[ap_index][ESSID] + W)
        # Set the channel as the choosen AP channel in order to send packets to connected devices later
        set_channel(int(APs_list[ap_index][CHANNEL]), interface)
        return APs_list[ap_index]
    else:
        # If no AP was found.
        rescan = input(B + "No networks were found. Do you want to rescan? [Y/n] " + W)
        if rescan == "n":
            print(R + "  Bye  " + W)
            deactivate_monitor(interface)
            sys.exit(0)
        else:
            APs_scanner(interface)


### In this fucntion we scan the network for devices which are connected to the choosen AP.
### We present all the available devices nearby and then the user can chose which one to attack.
def devices_scanner(interface, ap):
    print(P + "*** Step 3:  Choosing a target to attack. *** \n" + W)
    input(B + "Press Enter to continue........." + W)
    print(P + "\nScanning for devices that connected to: " + ap[ESSID] + " ..." + W)
    # Sniffing packets - scanning the network for devices which are connected to the chosen AP
    global network
    network = ap
    # We need the device to send packet to the AP and it may take time, in order to do so we double the scan time.
    sniff(iface=interface, prn=device_scan_pkt, timeout=search_time * 2)
    num_of_devices = len(users_list)
    # If at least one device was found, print all the found devices
    if num_of_devices > 0:
        # If at least 1 device was found.
        print(P + "\n*************** Devices Table ***************\n" + W)
        for x in range(num_of_devices):
            print("[" + str(x) + "] - " + users_list[x])
        print(P + "\n************** FINISH SCANNING **************\n" + W)
        # Choosing the AP to attack
        device_index = input(B +
                             "Please enter the number of the device you want to attack or enter 'R' if you want to rescan: " + W)
        if device_index == 'R':
            devices_scanner(interface, ap)
        elif device_index.isnumeric():
            # device was chosen
            # Print the chosen AP
            print(P + "You choose the device: [" + device_index + "] - " + users_list[int(device_index)] + W)
            return users_list[int(device_index)]
            # deauth_attack()
    else:
        # If no device was found during scanning.
        rescan = input(B + "No devices were found. Do you want to rescan? [Y/n] " + W)
        if rescan == "n":
            print(R + "  Bye.  " + W)
            deactivate_monitor(interface)
            sys.exit(0)
        else:
            devices_scanner(interface, ap)


### sniff(..., prn = device_scan_pkt, ...)
### The argument 'prn' allows us to pass a function that executes with each packet sniffed
def device_scan_pkt(pkt):
    # We are interested in packets that send from the chosen AP to a device (not broadcast)
    # ff:ff:ff:ff:ff:ff - broadcast address
    if pkt.haslayer(Dot11):
        if (pkt.addr2 == network[BSSID] or pkt.addr3 == network[BSSID]) and pkt.addr1 != "ff:ff:ff:ff:ff:ff":
            if pkt.addr1 not in users_list:
                if pkt.addr2 != pkt.addr1 and pkt.addr1 != pkt.addr3:
                    # Add the new-found device to the device list
                    users_list.append(pkt.addr1)
                    print(P + "Device with MAC address: " + pkt.addr1 + " was found." + W)


def choose_interface(flag):
    if flag == 1:
        print(P + "*** Step 1:  Choosing an interface to put in 'monitor mode'. *** \n")
    else:
        print(P + "*** Step 4:  Activate captive portal. *** \n" + W)
        input(B + "Press Enter to continue........." + W)
        print(P + "*** Choosing different interface to put in 'hotspot mode'. *** \n")
    input(B + "Press Enter to continue........." + W)
    os.system('ifconfig')
    if flag == 1:
        interface = input(B + "Please enter the interface name you want to put in 'monitor mode': " + W)
    else:
        interface = input(B + "Please enter the interface name you want to put in 'hotspot mode': " + W)
    return interface


def activate_monitor(interface):
    # Put the choosen interface in 'monitor mode'
    try:
        if os.system('ifconfig ' + interface + ' down') != 0:
            raise Exception()
        if os.system('iwconfig ' + interface + ' mode monitor') != 0:
            raise Exception()
        if os.system('ifconfig ' + interface + ' up') != 0:
            raise Exception()
    except:
        sys.exit(R + "can't activate monitor mode on " + interface + W)
    return interface


def deactivate_monitor(interface):
    try:
        print(P + "\n*** Step 5: Put the interface back in 'managed mode'. *** \n" + W)
        input(B + "Press Enter in order to put " + interface + " in 'managed mode' ........." + W)
        # Put the choosen interface back in 'managed mode'
        if os.system('ifconfig ' + interface + ' down') != 0:
            raise Exception()
        if os.system('iwconfig ' + interface + ' mode managed') != 0:
            raise Exception()
        if os.system('ifconfig ' + interface + ' up') != 0:
            raise Exception()
    except:
        sys.exit(R + "can't deactivate monitor mode on " + interface + W)
