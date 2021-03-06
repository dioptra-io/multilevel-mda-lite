import json
import pprint
from Graph.Operations import *
from Network.Packets.Utils import *


def extract_probe_size(g, ip_version):
    raw_probes_replies = g.graph_properties["raw_probes_replies"]
    if ip_version == "4":
        return raw_probes_replies[0][0][1][IP].len
    elif ip_version == "6":
        return raw_probes_replies[0][0][1][IPv6].len

def json_result_by_ttl(g, ip_version):
    raw_probes_replies = g.graph_properties["raw_probes_replies"]
    max_ttl = find_max_ttl(g)
    result = [{"hop": i, "result":[]} for i in range (1, max_ttl + 1)]

    for probe_, reply_ in raw_probes_replies:
        send_time = probe_[0]
        probe     = probe_[1]

        if reply_ == "*":
            reply = "*"
            rtt = None
        else:
            receive_time = reply_[0]
            reply = reply_[1]
            rtt = (receive_time - send_time) * 1000
        if ip_version == "4":
            ttl = extract_ttl(probe)
            flow_id = extract_flow_id_probe(probe)
            if reply == "*":
                result[ttl - 1]["result"].append({"x":"*",
                                                  "flow_id": flow_id
                                                  })
                continue
            else:
                src_addr = extract_src_ip(reply, IP)
                size_reply  = reply[IP].len
                ttl_reply   = extract_ttl(reply)

        elif ip_version == "6":
            ttl = extract_ttl6(probe)
            flow_id = extract_flow_id_probe6(probe)
            if reply == "*":
                result[ttl - 1]["result"].append({"x":"*",
                                                  "flow_id": flow_id
                                                  })
                continue
            else:
                src_addr = extract_src_ip(reply, IPv6)
                size_reply  = reply[IPv6].plen
                ttl_reply   = extract_ttl6(reply)
                flow_id = extract_flow_id_reply6(reply)
        result[ttl - 1]["result"].append(
            {
                "from": src_addr,
                "rtt": rtt,
                "size": size_reply,
                "ttl": ttl_reply,
                "flow_id": flow_id
            })
    return result

def dump_ripe_output(g, ip_version, algorithm, ofile):
    '''
    This outputs the traceroute in the RIPE format given in https://atlas.ripe.net/docs/data_struct/#v4750_traceroute
    enriched with the flow id.
    :param g:
    :return:
    '''

    source = g.graph_properties["source"]
    destination = g.graph_properties["destination"]
    ip_address = g.vertex_properties["ip_address"]


    if ip_version == "IPv4":
        af = "4"
    elif ip_version == "IPv6":
        af = "6"
    output = {
        "af": af,
        "dst_addr": destination,
        "dst_name": destination,
        "endtime" : g.graph_properties["end_time"],
        "from"    : ip_address[g.vertex(0)],
        "fw"      : 4790,
        "lts"     : -1,
        "msm_id"  : -1,
        "msm_name": algorithm,
        "paris_id": 0,
        # To be changed when other protocols will be available
        "proto"   : "UDP",
        "result"  : json_result_by_ttl(g, af),
        "size": extract_probe_size(g, af),
        "src_addr": source,
        "timestamp": g.graph_properties["starting_time"],
        "type": algorithm
    }

    with open(ofile, "w") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    import platform

    if platform.system() == "Darwin":
        from kamene import config

        config.conf.use_pcap = True
        config.conf.use_dnet = True
        from kamene.all import L3dnetSocket

        config.conf.L3socket = L3dnetSocket
    elif platform.system() == "Linux":
        from scapy import config
        from scapy.all import L3PacketSocket

        config.conf.L3socket = L3PacketSocket
    elif platform.system() == "Windows":
        from kamene import config

        config.conf.use_pcap = True
        config.conf.use_dnet = True
        from kamene.all import L3dnetSocket

        config.conf.L3socket = L3dnetSocket
    config.Conf.load_layers.remove("x509")
    from graph_tool.all import *
    g = load_graph("test.xml")
    dump_ripe_output(g, "IPv4", "mda-lite", "test.json")
