from netifaces import AF_INET, AF_INET6
import netifaces as ni

ip_version = "IPv4"

default_interface = None
default_ip_address_4 = None
default_ip_address_6 = None

# Find the first default interface with an IPv4 and an IPv6 address
interfaces = ni.interfaces()
for interface in interfaces:
    if interface.startswith("lo"):
        continue
    if AF_INET in ni.ifaddresses(interface):
        if "addr" in ni.ifaddresses(interface)[AF_INET][0]:
            default_interface = str(interface)
            default_ip_address_4 = str(ni.ifaddresses(default_interface)[AF_INET][0]['addr'])
        if AF_INET6 in ni.ifaddresses(interface):
            if "addr" in ni.ifaddresses(interface)[AF_INET6][0]:
                default_ip_address_6 = str(ni.ifaddresses(default_interface)[AF_INET6][0]['addr'])
                break

print ("default IP interface: " + str(default_interface))


print ('default IPv4 address: ' + str(default_ip_address_4))
print ("default IPv6 address: " + str(default_ip_address_6))

def set_ip_version(new_ip_version):
    global ip_version
    ip_version = new_ip_version

def get_ip_version():
    return ip_version


def set_interface(interface):
    global default_interface
    global default_ip_address_4
    global default_ip_address_6
    default_interface = interface
    if AF_INET in ni.ifaddresses(interface):
        default_ip_address_4 = ni.ifaddresses(default_interface)[AF_INET][0]['addr']
    if AF_INET6 in ni.ifaddresses(interface) and 'addr' in interface[AF_INET6][0]:
        default_ip_address_6 = ni.ifaddresses(default_interface)[AF_INET6][0]['addr']
def get_interface():
    return default_interface

def set_ip_address(ip):
    global default_ip_address_4
    default_ip_address_4 = ip

def set_ip_address6(ip):
    global default_ip_address_6
    default_ip_address_6 = ip