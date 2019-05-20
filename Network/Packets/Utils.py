from scapy.contrib.icmp_extensions import ICMPExtensionMPLS
from scapy.packet import NoPayload
from scapy.layers.inet import IP, ICMP, UDP, IPerror, UDPerror
from Maths.Bounds import get_nks

from Network.Config import default_ip_address_4, default_ip_address_6, get_ip_version

from scapy.layers.inet6 import IPv6, ICMPv6TimeExceeded, ICMPv6DestUnreach, IPerror6
# Hardcoded sport
sport  = 24000
# Hardcoded dport
dport  = 33435
# Hardcoded max_ttl

#nk to ensure 5% failure probability
nk95, nk99 = get_nks()

def build_icmp_echo_request_probe(destination):
    return IP(src=default_ip_address_4, dst=destination) / ICMP()


def build_ipv6_probe(destination, ttl, flow_id):
    # i = IPv6()
    # i.dst = "google.fr"
    # q = ICMPv6EchoRequest()
    # p = i / q
    # reply, no_reply = sr(p, timeout = 1)

    return IPv6(src=default_ip_address_6, dst=destination, fl=flow_id, hlim = ttl, nh=17)


def build_probe(destination, ttl, flow_id):
    using_ip_version = get_ip_version()
    if using_ip_version == "IPv4":
        ip = build_ip_probe(destination, ttl)
        udp = build_transport_probe(flow_id)
        raw = build_raw_probe("")
        return ip/udp/raw
    elif using_ip_version == "IPv6":
        ip = build_ipv6_probe(destination, ttl, flow_id)
        udp = build_transport_probe(flow_id)
        raw = build_raw_probe("")
        return ip/udp/raw
    raise Exception("Please choose between IPv4 and IPv6")


def build_ip_probe(destination, ttl):
    return IP(dst=destination, ttl=ttl)

def build_transport_probe(flow_id):
    return UDP(dport = dport, sport = sport + flow_id)
def build_raw_probe(data):
    return data

def build_alias_probe(destination):
    return IP(dst = destination)/ICMP()

# 1 protocol for prototyping, UDP
# Must write vertex_confidence
def get_phase_1_probe(destination, ttl, nks, black_flows):
    white_flows = []
    i = 0
    while len(white_flows) < nks[2]:
        i += 1
        if i not in black_flows:
            white_flows.append(i)
    probes = []
    for j in white_flows:
        probes.append(build_probe(destination, ttl, j))
    return probes

def extract_send_time(p):
    return p.sent_time

def extract_time(p):
    return p[IP].time

def extract_src_ip(p, ip_type=IP):
    return p[ip_type].src

def extract_flow_id_reply(reply):
    return reply[ICMP].sport - sport

def extract_flow_id_reply6(reply):
    return reply[IPerror6].fl

def extract_flow_id_probe(probe):
    return probe[UDP].sport - sport

def extract_flow_id_probe6(probe):
    return probe[IPv6].fl

def extract_ttl(p):
    return p[IP].ttl

def extract_ttl6(reply):
    return reply[IPv6].hlim

def extract_ip_id(reply):
    return reply[IP].id

def extract_icmp_reply_infos(reply):
    ip_version = get_ip_version()
    ip_type = None
    if ip_version == "IPv4":
        udp_error = reply[IP][ICMP][IPerror][UDPerror]
        ip_type = IP
    elif ip_version == "IPv6":
        ip_type = IPv6
        if type(reply[IPv6].payload) == ICMPv6TimeExceeded:
            udp_error = reply[IPv6][ICMPv6TimeExceeded][IPerror6][UDPerror]
        elif type(reply[IPv6].payload) == ICMPv6DestUnreach:
            udp_error = reply[IPv6][ICMPv6DestUnreach][IPerror6][UDPerror]
    else:
        raise Exception("IP version not defined.")
    # udp_error.post_dissection(reply)
    # udp_error.
    # Extract MPLS infos

    icmp_extension = udp_error.payload.payload.payload
    mpls_infos = None
    if type(icmp_extension) != NoPayload:
        if type(icmp_extension.payload) == ICMPExtensionMPLS:
            # Extract MPLS stack
            mpls_stack = icmp_extension.payload.fields["stack"][0].fields
            mpls_infos = mpls_stack

    src_ip = extract_src_ip(reply, ip_type)
    if ip_type == IP:
        flow_id = extract_flow_id_reply(reply)
        ttl = extract_ttl(reply)
        ip_id = extract_ip_id(reply)
    else:
        flow_id = extract_flow_id_reply6(reply)
        ttl = extract_ttl6(reply)
        ip_id = None
    return src_ip, flow_id, ttl, ip_id, mpls_infos

def extract_probe_infos(probe):
    ip_version = get_ip_version()
    if ip_version == "IPv4":
        ttl = extract_ttl(probe)
        ip_id = extract_ip_id(probe)
    elif ip_version == "IPv6":
        ttl = extract_ttl6(probe)
        ip_id = None

    return ttl, ip_id
