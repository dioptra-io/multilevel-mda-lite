import sys
import logging

from graph_tool.all import *
from Graph.LoadBalancer import *
from Algorithm.Constants import *
from Network.Config import *


max_ttl = 30

def init_graph(destination):
    global ip_version
    g = Graph()

    source_prop = g.new_graph_property("string")
    if ip_version == "IPv4":
        source_prop[g] = default_ip_address_4
    elif ip_version == "IPv6":
        source_prop[g] = default_ip_address_6

    destination_prop = g.new_graph_property("string")
    destination_prop[g] = destination
    g.graph_properties["destination"] = destination_prop
    g.graph_properties["source"] = source_prop


    ip_address = g.new_vertex_property("string")
    ttls_flow_ids = g.new_vertex_property("python::object")

    inferred = g.new_edge_property("bool", False)
    edge_flows = g.new_edge_property("python::object")

    ip_ids = g.new_vertex_property("python::object")

    # Corresponds to fingerprinting to classify routers.
    # Two elements in this list, first is the ttl reply on an ICMP echo request, second is on time exceeded.
    finger_printing = g.new_vertex_property("vector<int>")

    # RFC 4950, we can have MPLS Infos for free (when MPLS tunnel is visible).
    mpls  = g.new_vertex_property("python::object")

    # Raw probes for RIPE Json output
    raw_probes_replies = g.new_graph_property("python::object")

    raw_probes_replies[g] = []
    g.graph_properties["raw_probes_replies"] = raw_probes_replies

    g.vertex_properties["ip_address"] = ip_address
    g.vertex_properties["ttls_flow_ids"] = ttls_flow_ids
    g.vertex_properties["ip_ids"] = ip_ids
    g.vertex_properties["fingerprinting"] = finger_printing
    g.vertex_properties["mpls"] = mpls
    g.edge_properties["inferred"] = inferred
    g.edge_properties["edge_flows"] = edge_flows
    source = g.add_vertex()
    ip_version = get_ip_version()
    if ip_version == "IPv4":
        ip_address[source] = default_ip_address_4
    elif ip_version == "IPv6":
        ip_address[source] = default_ip_address_6
    ttls_flow_ids[source] = {}
    ttls_flow_ids[source][0] = []
    for i in range (1, 5000):
        ttls_flow_ids[source][0].append(i)
    mpls[source] = []
    return g

def has_common_neighbor(v1, v2):
    for pred1 in v1.in_neighbors():
        for pred2 in v2.in_neighbors():
            if pred1 == pred2:
                return True
    return False
def find_vertex_by_ip(g, ip):
    ip_address = g.vertex_properties["ip_address"]
    for v in g.vertices():
        if ip_address[v] == ip:
            return v
    return None

def find_vertex_by_ttl(g, ttl):
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    vertices_ttl = []
    for v in g.vertices():
        for hop, flow_ids in ttls_flow_ids[v].items():
            if hop == ttl:
                vertices_ttl.append(v)
    return vertices_ttl

def find_vertex_by_ttl_flow_id(g, ttl, flow_id):
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    v_ttl_flow_id = []
    for v in g.vertices():
        for hop, flow_ids in ttls_flow_ids[v].items():
            if hop == ttl and flow_id in flow_ids:
                v_ttl_flow_id.append(v)
    if len(v_ttl_flow_id) > 0:
        return v_ttl_flow_id
    return None


def find_neighbors_ttl(g, v, ttl, ttl2):
    # Here just filter on out_neighbors does not work because the nodes could be neighbors
    # for another ttl

    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    vflow_ids = ttls_flow_ids[v][ttl]
    potential_predecessors = find_vertex_by_ttl(g, ttl2)
    predecessors = []
    for pred in potential_predecessors:
        for hop, flow_ids in ttls_flow_ids[pred].items():
            if hop == ttl2:
                l = len(set(flow_ids).intersection(vflow_ids))
                if l != 0:
                    predecessors.append(pred)
    return predecessors

def find_predecessors_ttl(g, v, ttl):
    return find_neighbors_ttl(g, v, ttl, ttl-1)

def find_successors_ttl(g, v, ttl):
    return find_neighbors_ttl(g, v, ttl, ttl+1)

# Find the maximum TTL in g
def find_max_ttl(g):
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    ttls = set()
    for v in g.vertices():
        for ttl, flow_id in ttls_flow_ids[v].items():
            ttls.add(ttl)
    return max(ttls)

def find_max_flow_id(g, ttl):
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    max_flow_id = -1
    for v in g.vertices():
        for hop, flow_ids in ttls_flow_ids[v].items():
            if hop == ttl:
                for flow_id in flow_ids:
                    if flow_id > max_flow_id:
                        max_flow_id = flow_id

    black_flows_ttl = black_flows[ttl]
    if len(black_flows_ttl) > 0 :
        max_flow_id = max(max(black_flows_ttl), max_flow_id)
    return max_flow_id

def find_probes_sent(g, ttl):
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    count = 0
    for v in g.vertices():
        for hop, flow_ids in ttls_flow_ids[v].items():
            if hop == ttl:
                count = count + len(flow_ids)
    return count

def find_flows(g, ttl):
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    flows_ids_ttl = []
    for v in g.vertices():
        for hop, flow_ids in ttls_flow_ids[v].items():
            if hop == ttl:
                flows_ids_ttl.extend(flow_ids)
    return flows_ids_ttl

# Find flows that are
def find_missing_flows(g, ttl, ttl2):
    flows_ids_ttl = sorted(find_flows(g, ttl))
    flows_ids_ttl2 = sorted(find_flows(g, ttl2))

    missing_flows = []
    for flow1 in flows_ids_ttl:
        if flow1 not in flows_ids_ttl2:
            missing_flows.append(flow1)
    return sorted(missing_flows)


def dump_flows(g):
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    for i in range(1, 30):
        print (sorted(find_flows(g, i)))
    return

def tag_edge_flow(g, e, src_ttl, dst_ttl, flow_id, is_new_edge):
    edge_flows = g.edge_properties["edge_flows"]
    if is_new_edge:
        edge_flows[e] = {}
        edge_flows[e]["flows"] = []
    edge_flows[e]["flows"].append({"flow_id": flow_id, "src_ttl":src_ttl, "dst_ttl": dst_ttl})
def update_neigbours(g, v, ttl, flow_id):
    # Add the corresponding edges if there are to be added
    successors = find_vertex_by_ttl_flow_id(g, ttl+1, flow_id)
    if successors is not None:
        for successor in successors:
            # Multiple edges are not possible here
            e = g.edge(v, successor)
            if e is None:
                e = g.add_edge(v, successor)
                tag_edge_flow(g, e, ttl, ttl+1, flow_id, True)
            else:
                tag_edge_flow(g, e, ttl, ttl+1, flow_id, False)
    predecessors = find_vertex_by_ttl_flow_id(g, ttl-1, flow_id)
    if predecessors is not None:
        for predecessor in predecessors:
            e = g.edge(predecessor, v)
            if e is None:
                e = g.add_edge(predecessor, v)
                tag_edge_flow(g, e, ttl-1, ttl, flow_id, True)
            else:
                tag_edge_flow(g, e, ttl-1, ttl, flow_id, False)
def init_vertex(g, v, ip, ttl_reply):
    ip_address = g.vertex_properties["ip_address"]
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    ip_ids = g.vertex_properties["ip_ids"]
    fingerprinting = g.vertex_properties["fingerprinting"]
    mpls = g.vertex_properties["mpls"]
    ip_address[v] = ip
    fingerprinting[v] = [0, 0]
    fingerprinting[v][1] = ttl_reply
    # Filling of first ttl flow ids is done in update neighbours.
    ttls_flow_ids[v] = {}
    ip_ids[v] = []
    mpls[v] = []

def add_new_vertex(g, ip, ttl_reply):
    v = g.add_vertex()
    # Initialize the vertex
    init_vertex(g, v, ip, ttl_reply)
    return v

def update_vertex(g, v, ttl, flow_id, alias_result, mpls_infos):
    ip_ids = g.vertex_properties["ip_ids"]
    mpls = g.vertex_properties["mpls"]
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    if ttl in ttls_flow_ids[v]:
        ttls_flow_ids[v][ttl].append(flow_id)
    else:
        ttls_flow_ids[v][ttl] = [flow_id]
    if len(alias_result) > 0:
        ip_ids[v].append(alias_result)
    if mpls_infos is not None:
        mpls[v].append(mpls_infos)

def update_graph(g, ip, ttl, ttl_reply, flow_id, alias_result, mpls_infos):
    ip_address = g.vertex_properties["ip_address"]
    already_discovered = False
    for v in g.vertices():
        if ip_address[v] == ip:
            update_vertex(g, v, ttl, flow_id, alias_result, mpls_infos)
            update_neigbours(g, v, ttl, flow_id)
            already_discovered = True
            break

    if not already_discovered:
        v = add_new_vertex(g, ip, ttl_reply)
        update_vertex(g, v, ttl, flow_id, alias_result, mpls_infos)
        update_neigbours(g, v, ttl, flow_id)
    return g

def dict_vertices_by_ttl(g):
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    dict_vertices_by_ttl = {}
    for v in g.vertices():
        for ttl, flow_ids in ttls_flow_ids[v].items():
            if ttl not in dict_vertices_by_ttl:
                dict_vertices_by_ttl[ttl] = [v]
            else:
                dict_vertices_by_ttl[ttl].append(v)

    return dict_vertices_by_ttl

def dict_vertices_by_ttl_without_useless_stars(g):
    # Don't take stars into account except if it is the only interface seen at this hop
    ip_address    = g.vertex_properties["ip_address"]
    vertices_by_ttl = dict_vertices_by_ttl(g)
    for ttl, vertices in vertices_by_ttl.items():
        wstar_vertices = list(filter(lambda v : not ip_address[v].startswith("*"), vertices))
        if len(wstar_vertices) != 0:
            vertices_by_ttl[ttl] = wstar_vertices
    return vertices_by_ttl

def find_consecutive_sequence(s):
    ll = []
    l= []
    for i in range(0, len(s)):
        if i == 0 or s[i - 1] + 1 == s[i]:
            l.append(s[i])
        else:
            ll.append(list(l))
            l = []
            l.append(s[i])
    ll.append(l)
    return ll

def find_consecutive_ttls(ttls_vertices):
    ttls = []
    for ttl, vertices in ttls_vertices:
        ttls.append(ttl)
    sorted_ttls = sorted(ttls)
    return find_consecutive_sequence(sorted_ttls)


def extract_load_balancers(g):
    vertices_by_ttl = dict_vertices_by_ttl_without_useless_stars(g)
    ttls = []
    for ttl, vertices in vertices_by_ttl.items():
        if len(vertices) > 1:
            ttls.append((ttl, vertices))

    load_balancers = []
    consecutive_ttls = find_consecutive_ttls(ttls)
    for l in consecutive_ttls:
        lb = {}
        for ttl in l :
            lb[ttl] = len(vertices_by_ttl[ttl])
        load_balancers.append(LoadBalancer(lb))
    return load_balancers

def find_no_predecessor_vertices(g, ttl):
    result = []
    vertices_ttl = find_vertex_by_ttl(g, ttl)
    for v in vertices_ttl:
        if v.in_degree() == 0:
            result.append(v)
    return result

def find_no_successor_vertices(g, ttl):
    result = []
    vertices_ttl = find_vertex_by_ttl(g, ttl)
    for v in vertices_ttl:
        if v.out_degree() == 0:
            result.append(v)
    return result

def apply_multiple_predecessors_heuristic(g, ttl):
    # Find if the the interfaces at ttl have common predecessors

    interfaces = find_vertex_by_ttl(g, ttl)
    max_in_neighbor = 0
    for interface in interfaces:
        distinct_neighbors = set(interface.in_neighbors())
        if len(distinct_neighbors) > max_in_neighbor:
            max_in_neighbor = len(distinct_neighbors)
    return max_in_neighbor > 1

def apply_multiple_successors_heuristic(g, ttl):
    # Find if the the interfaces at ttl have common successors

    interfaces = find_vertex_by_ttl(g, ttl)
    max_out_neighbor = 0
    for interface in interfaces:
        distinct_neighbors = set(interface.out_neighbors())
        if len(distinct_neighbors) > max_out_neighbor:
            max_out_neighbor = len(distinct_neighbors)
    return max_out_neighbor > 1

def apply_converging_heuristic(g, ttl, forward, backward):
    # This heuristic just infer divergence and then reconvergence
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]

    inferred = g.edge_properties["inferred"]
    lv_successor = find_vertex_by_ttl(g, ttl+1)

    lv_predecessor = find_vertex_by_ttl(g, ttl - 1)
    v_successor = lv_successor[0]
    v_successor_flow_ids = ttls_flow_ids[v_successor][ttl+1]

    v_predecessor = lv_predecessor[0]
    v_predecessor_flow_ids = ttls_flow_ids[v_predecessor][ttl - 1]
    for v in g.vertices():
        for hop, flow_ids in ttls_flow_ids[v].items():
            if hop == ttl:
                if forward:
                    if len(set(flow_ids).intersection(v_successor_flow_ids)) == 0:
                        e = g.add_edge(v, v_successor)
                        inferred[e] = True
                if backward:
                    if len(set(flow_ids).intersection(v_predecessor_flow_ids)) == 0:
                        e = g.add_edge(v_predecessor, v)
                        inferred[e] = True

# max_diff_degree_arg represents the level of inference that we want to put
def apply_symmetry_heuristic(g, ttl, max_diff_degree_arg):
    inferred = g.edge_properties["inferred"]
    vertices_ttl = find_vertex_by_ttl(g, ttl)

    neighbors_by_vertices = {}
    for v in vertices_ttl:
        neighbors_by_vertices[v] = list(v.out_neighbors())
    # If a node has more than strength neigbors in common, infer links
    for v1, out_neighbors1 in neighbors_by_vertices.items():
        for v2, out_neighbors2 in neighbors_by_vertices.items():
            if v1 == v2:
                continue
            difference = set(out_neighbors1).difference(out_neighbors2)
            if len(difference) < max_diff_degree_arg and len(out_neighbors1) > 3:
                # Add the inferences
                for d in difference:
                    e = g.add_edge(v2, d)
                    inferred[e] = True

def is_a_divergent_ttl(g, ttl):
    vertices_ttl = find_vertex_by_ttl(g, ttl)
    vertices_ttl_pred = find_vertex_by_ttl(g, ttl -1)
    return len(vertices_ttl) >= len(vertices_ttl_pred)

def out_degrees_ttl(g, ttl):
    vertices_ttl_pred = find_vertex_by_ttl(g, ttl)
    distinct_succ_number = []
    for v in vertices_ttl_pred:
        distinct_succ_number.append(v.out_degree())
    return distinct_succ_number

def in_degrees_ttl(g, ttl):
    vertices_ttl_pred = find_vertex_by_ttl(g, ttl)
    distinct_succ_number = []
    for v in vertices_ttl_pred:
        distinct_succ_number.append(v.in_degree())
    return distinct_succ_number

def is_new_ip(g, ip):
    ip_address = g.vertex_properties["ip_address"]
    for v in g.vertices():
        if ip_address[v] == ip:
            return False
    return True

def has_discovered_edge(g, ip, ttl, flow_id):
    v = find_vertex_by_ip(g, ip)
    if v is None :
        return True
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    potential_predecessors = find_vertex_by_ttl(g, ttl - 1)
    for p in potential_predecessors:
        for hop, flow_ids in ttls_flow_ids[p].items():
            if hop == ttl - 1 and flow_id in flow_ids:
                if v not in p.out_neighbors():
                    return True
    return False

def merge_vertices(g, v1, v2):
    interfaces = g.vertex_properties["interfaces"]
    ip_address = g.vertex_properties["ip_address"]

    interfaces[v1].append(ip_address[v1])
    interfaces[v1].append(ip_address[v2])
    for succ in v2.out_neighbors():
        g.add_edge(v1, succ)

    for pred in v2.in_neighbors():
        g.add_edge(pred, v1)


# Switch to standard MDA implementation
def mda_continue_probing_ttl(g, hop, nks):
    vertices_ttl = find_vertex_by_ttl(g, hop)
    vertices_successors = find_vertex_by_ttl(g, hop + 1)
    if len(vertices_successors) == 0 :
        return True
    for v in vertices_ttl:
        if mda_continue_probing_v(g, hop, v, nks):
            return True
    logging.info("TTL " + str(hop) + " finished. MDA Statistical guarantees reached.")
    return False

def mda_continue_probing_v(g, hop, v, nks):
    successors_ttl = len(find_successors_ttl(g, v, hop))
    flows, black_flows_v = forwarded_flows(g, v, hop)
    if len(flows) == 0 and len(black_flows_v) == 0:
        # Nothing has been forwarded yet
        return True

    # Only black flowds, stop.
    if len(flows) == 0 and len(black_flows_v) >= nks[successors_ttl + 1]:
        return False

    # If some responsive flows.
    return len(flows) < nks[successors_ttl + 1]


def forwarded_flows(g, v, ttl):
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    flows = []
    black_flows_v = []
    # Now extract the flows that were not sent at ttl + 1
    for flow_id in ttls_flow_ids[v][ttl]:
        if flow_id in black_flows[ttl + 1]:
            black_flows_v.append(flow_id)
            continue
        # Look if the flow has already been used.
        successor_flow_ttl_v = find_vertex_by_ttl_flow_id(g, ttl + 1, flow_id)
        # Look if this flow is in the black flows
        if successor_flow_ttl_v is not None:
            flows.append(flow_id)
    return flows, black_flows_v

def clean_stars(g):
    ip_address = g.vertex_properties["ip_address"]
    stars_to_remove = []
    for ttl in range(1, max_ttl+1):
        vertices = find_vertex_by_ttl(g, ttl)
        if len(vertices) > 0:
            star_to_remove = None
            has_only_star = True
            for v in vertices:
                if not ip_address[v].startswith("*"):
                    has_only_star = False
                else:
                    star_to_remove = v
            if not has_only_star and star_to_remove is not None:
                stars_to_remove.append(star_to_remove)
    for star_to_remove in reversed(sorted(stars_to_remove)):
        #print ip_address[star_to_remove]
        g.remove_vertex(star_to_remove)

def enrich_flow_data(flow, source_ip, destination, protocol, default_src_port, default_dst_port):
    flow["src_ip"] = source_ip
    flow["dst_ip"] = destination
    flow["protocol"] = protocol
    flow["src_port"] = flow["flow_id"] + default_src_port
    flow["dst_port"] = default_dst_port


def enrich_flows(g, source_ip, destination, protocol, default_src_port, default_dst_port):
    edge_flows = g.edge_properties["edge_flows"]
    for e in g.edges():
        flows = edge_flows[e]
        if "flows" in flows:
            for flow in flows["flows"]:
                enrich_flow_data(flow, source_ip, destination, protocol, default_src_port, default_dst_port)

def dump_results(g, with_alias_resolution, with_ip_to_as, destination):
    ip_address = g.vertex_properties["ip_address"]
    if with_ip_to_as:
        ripe_asns = g.vertex_properties["ripe_asns"]

    mpls = g.vertex_properties["mpls"]
    mpls_str = " (MPLS)"
    dump_ripe_asns = {}
    dump_mpls = {}
    for v in g.vertices() :
        if len(mpls[v]) > 0:
            dump_mpls[v] = mpls_str
        else:
            dump_mpls[v] = ""
        if with_ip_to_as:
            dump_ripe_asns[v] = ""
            if ripe_asns[v] is not None:
                for as_infos in ripe_asns[v]:
                    dump_ripe_asns[v] = dump_ripe_asns[v] + " (" + str(as_infos["holder"].encode("utf-8")) + ", " +str(as_infos["asn"]) + ")"
    # The format is the following : (ttl) : [ip->[successors], ...]
    for ttl in range(0, max_ttl):
        vertices_by_ttl = find_vertex_by_ttl(g, ttl)
        if len(vertices_by_ttl) > 0:
            sys.stdout.write("("+ str(ttl)+") : ")
            for v in vertices_by_ttl:
                if ip_address[v] != destination:
                    infos = ip_address[v]  + dump_mpls[v]
                    if with_ip_to_as:
                        infos = infos + str(dump_ripe_asns[v])
                    sys.stdout.write(infos + " -> ")
                    addresses = [ip_address[succ] + dump_mpls[succ] for succ in list(v.out_neighbors())]
                    sys.stdout.write(str(addresses))
                    sys.stdout.write("\n")
                else:
                    sys.stdout.write(ip_address[v])
            sys.stdout.write("\n")
            sys.stdout.flush()

    if with_alias_resolution:
        dump_routers(g)

def dump_routers_round(round, r_g):
    routers_round = r_g.graph_properties["routers_round_"+ str(round)]
    print ("Routers found for round "+str(round) +": ")
    for router in routers_round[0]:
        print (router)
    print ("Probes sent for round " + str(round) + ": " +str(routers_round[1]))
    print ("Replies received for round " + str(round) + ": " + str(routers_round[2]))

def dump_routers(r_g):
    routers = r_g.graph_properties["routers"]
    print ("Routers found : ")
    for router in routers:
        print (router)


############################## REMAPPING OPERATIONS #################################
def find_common_flow(g, e):
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    source = e.source()
    target = e.target()
    # Find the common flow
    for ttl_source, flow_ids_source in ttls_flow_ids[source].items():
        for ttl_target, flow_ids_target in ttls_flow_ids[target].items():
            if ttl_source + 1 == ttl_target:
                for flow_id_source in flow_ids_source:
                    for flow_id_target in flow_ids_target:
                        if flow_id_source == flow_id_target:
                            return (ttl_source, ttl_target, flow_id_source)


if __name__ == "__main__":
    seq = [1, 2, 4, 5, 7, 8]
    ll = find_consecutive_sequence(seq)
    assert ll == [[1, 2], [4, 5], [7,8]]
    seq = [1, 2, 4, 5, 7, 9]
    ll = find_consecutive_sequence(seq)
    assert ll == [[1, 2], [4, 5], [7], [9]]
    seq = [1, 2, 4, 6, 7, 9]
    ll = find_consecutive_sequence(seq)
    assert ll == [[1, 2],[4], [6, 7], [9]]