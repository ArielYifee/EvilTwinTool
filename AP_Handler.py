from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt

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


#  After the user choose the AP he want to attack, we want to set the interface's channel to the same channel as the choosen AP.
def set_channel(channel, interface):
    if os.system('iwconfig %s channel %d' % (interface, channel)) != 0:
        sys.exit("can't switch between channels")


def APs_scanner(interface):
    print("*** Step 2:  Choosing an network to attack. *** \n")
    input("Press Enter to continue.........")
    channel_changer = threading.Thread(target=change_channel, args=(interface,))
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
        # Set the channel as the choosen AP channel in order to send packets to connected devices later
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
            APs_scanner(interface)


### In this fucntion we scan the network for devices who are connected to the choosen AP.
### We present to the user all the devices that were found, and he choose which device he want to attack.
def devices_scanner(interface, ap):
    print("\nScanning for devices that connected to: " + ap[ESSID] + " ...")
    # Sniffing packets - scanning the network for devices which are connected to the choosen AP
    global network
    network = ap
    # We need the device to send packet to the AP and it may take time, so we double the scan time
    sniff(iface=interface, prn=device_scan_pkt, timeout=search_time * 2)
    num_of_devices = len(users_list)
    # If at least one device was found, print all the found devices
    if num_of_devices > 0:
        # If at least 1 device was found.
        print("\n*************** Devices Table ***************\n")
        for x in range(num_of_devices):
            print("[" + str(x) + "] - " + users_list[x])
        print("\n************** FINISH SCANNING **************\n")
        # Choosing the AP to attack
        device_index = input(
            "Please enter the number of the device you want to attack or enter 'R' if you want to rescan: ")
        if device_index == 'R':
            # Rescan
            devices_scanner(interface, ap)
        elif device_index.isnumeric():
            # device was chosen
            # Print the chosen AP
            print("You choose the device: [" + device_index + "] - " + users_list[int(device_index)])
            return users_list[int(device_index)]
            # deauth_attack()
    else:
        # If no device was found.
        rescan = input("No devices were found. Do you want to rescan? [Y/n] ")
        if rescan == "n":
            print("  Sorry :(  ")
            deactivate_monitor(interface)
            sys.exit(0)
        else:
            devices_scanner(interface, ap)


### sniff(..., prn = device_scan_pkt, ...)
### The argument 'prn' allows us to pass a function that executes with each packet sniffed
def device_scan_pkt(pkt):
    # We are interested in packets that send from the chosen AP to a device (not broadcast)
    # ff:ff:ff:ff:ff:ff - broadcast address
    if (pkt.addr2 == network[BSSID] or pkt.addr3 == network[BSSID]) and pkt.addr1 != "ff:ff:ff:ff:ff:ff":
        if pkt.addr1 not in users_list:
            if pkt.addr2 != pkt.addr1 and pkt.addr1 != pkt.addr3:
                # Add the new-found device to the device list
                users_list.append(pkt.addr1)
                print("Device with MAC address: " + pkt.addr1 + " was found.")


def choose_interface(flag):
    if flag == 1:
        print("*** Step 1:  Choosing an interface to put in 'monitor mode'. *** \n")
    else:
        print("*** Choosing different interface to put in 'hotspot mode'. *** \n")
    input("Press Enter to continue.........")
    os.system('ifconfig')
    if flag == 1:
        interface = input("Please enter the interface name you want to put in 'monitor mode': ")
    else:
        interface = input("Please enter the interface name you want to put in 'hotspot mode': ")
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
        sys.exit("can't activate monitor mode on " + interface)
    return interface


def deactivate_monitor(interface):
    try:
        print("\n*** Step 5: Put the interface back in 'managed mode'. *** \n")
        input("Press Enter in order to put " + interface + " in 'managed mode' .........")
        # Put the choosen interface back in 'managed mode'
        if os.system('ifconfig ' + interface + ' down') != 0:
            raise Exception()
        if os.system('iwconfig ' + interface + ' mode managed') != 0:
            raise Exception()
        if os.system('ifconfig ' + interface + ' up') != 0:
            raise Exception()
    except:
        sys.exit("can't deactivate monitor mode on " + interface)
