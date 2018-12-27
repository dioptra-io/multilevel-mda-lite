import requests

def ripe_ip2as(g):
    ip_address = g.vertex_properties["ip_address"]
    ripe_asns = g.new_vertex_property("python::object")
    g.vertex_properties["ripe_asns"] = ripe_asns

    distinct_asns = set()

    # Get the IP to AS informations from two sources: https://stat.ripe.net/data/prefix-overview/ and https://bgpstream.caida.org/docs/tutorials/pybgpstream
    ripe_ip2as_url = "https://stat.ripe.net/data/prefix-overview/data.json?resource="

    for v in g.vertices():
        result = requests.get(ripe_ip2as_url+ ip_address[v])
        as_infos = result.json()["data"]
        if "asns" in as_infos:
            asns = as_infos["asns"]
            ripe_asns[v] = asns
            if len(asns) > 0:
                for asn_infos in asns:
                    asn = asn_infos["asn"]
                    distinct_asns.add(asn)


    ripe_distinct_asns = g.new_graph_property("python::object")
    g.graph_properties["ripe_asns"] = ripe_distinct_asns
    ripe_distinct_asns[g] = list(distinct_asns)




