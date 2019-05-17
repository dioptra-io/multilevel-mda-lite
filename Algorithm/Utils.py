# This file contains step of algorithms that are/could be shared by the different algorithms.


import logging
import time
from Algorithm.Constants import *
from Graph.Operations import *
from scapy.sendrecv import sr
from Network.Config import default_interface
from Network.Packets.Utils import *

def execute_phase1(g, destination, nks):
    has_found_longest_path_to_destination = False
    consecutive_only_star = 0
    ttl = 1
    while not has_found_longest_path_to_destination and ttl < max_ttl:
        if consecutive_only_star == default_stop_on_consecutive_stars:
            logging.info(str(default_stop_on_consecutive_stars) + " consecutive hop with only stars found, stopping the algorithm, passing to next step")
            return True
        total_replies_ttl = 0
        replies_only_from_destination = True
        while total_replies_ttl < nks[2]:
            next_flow_id = max(find_max_flow_id(g, ttl), 0)
            phase1_probes = generate_probes(nks[2] - total_replies_ttl, destination, ttl, next_flow_id)
            replies, unanswered = send_probes(phase1_probes, default_timeout, True)
            total_replies_ttl += len(replies)
            if len(replies) == 0:
                if total_replies_ttl == 0 :
                    consecutive_only_star = consecutive_only_star + 1
                replies_only_from_destination = False
                update_unanswered(unanswered, ttl, True, g)
                break
            else:
                consecutive_only_star = 0
                update_unanswered(unanswered, ttl, False, g)

            # Update the graph
            update_graph_from_replies(g, replies)

            # Additional checks specific to the algorithm phase.
            for probe, reply in replies:
                src_ip, flow_id, ttl_reply, ip_id_reply, mpls_infos = extract_icmp_reply_infos(reply)
                print (src_ip)
                if src_ip != destination:
                    replies_only_from_destination = False
        if replies_only_from_destination:
            has_found_longest_path_to_destination = True
        ttl = ttl + 1
    return False

def init_black_flows():
    for i in range(0, max_ttl + 1):
        black_flows[i] = []

def increment_replies(n):
    global total_replies
    total_replies += n

def increment_probe_sent(n):
    global total_probe_sent
    total_probe_sent += n

def get_total_probe_sent():
    return total_probe_sent

def get_total_replies():
    return total_replies

def generate_probes(nprobes, destination, ttl, starting_flow_id):

    probes = []
    if nprobes > 0 :
        j = starting_flow_id
        while len(probes) < nprobes:
            j += 1
            if j not in black_flows[ttl - 1]:
                probes.append(build_probe(destination, ttl, j))
    return probes

def send_probes(probes, timeout, verbose = False):
    replies, unanswered = sr(probes, timeout=timeout, verbose=verbose, iface=default_interface)
    # after =  time.time()
    increment_probe_sent(len(probes))
    increment_replies(len(replies.res))
    return replies, unanswered

def update_graph_from_replies(g, replies):
    for probe, reply in replies:
        src_ip, flow_id, ttl_reply, ip_id_reply, mpls_infos = extract_icmp_reply_infos(reply)
        ttl_probe, ip_id_probe = extract_probe_infos(probe)
        alias_result = [probe.sent_time, reply.time, ip_id_reply, ip_id_probe]
        # Update the graph
        g.graph_properties["raw_probes_replies"].append([[probe.sent_time, probe], [reply.time, reply]])
        g = update_graph(g, src_ip, ttl_probe, ttl_reply, flow_id, alias_result, mpls_infos)


def update_unanswered(unanswered, ttl, is_only_star, g):

    for probe in unanswered:
        g.graph_properties["raw_probes_replies"].append([[probe.sent_time, probe], "*"])
        flow_id = extract_flow_id_probe(probe)
        if is_only_star:
            src_ip = "* * * " + str(ttl)
            # Update the graph
            g = update_graph(g, src_ip, ttl, -1, flow_id, [], None)

        black_flows[ttl].append(flow_id)

def adapt_sending_rate(adaptive_icmp_rate, last_loss_fraction, adaptive_timeout, ttl, replies, unanswered):
    if last_loss_fraction[ttl] >= float(len(unanswered)) / len(replies):
        adaptive_icmp_rate[ttl] += int(batching_growth * adaptive_icmp_rate[ttl])
        last_loss_fraction[ttl] = float(len(unanswered)) / len(replies)
        adaptive_timeout[ttl] += 1
    elif last_loss_fraction[ttl] < float(len(unanswered)) / len(replies):
        adaptive_icmp_rate[ttl] -= int(batching_growth * adaptive_icmp_rate[ttl])
        last_loss_fraction[ttl] = float(len(unanswered)) / len(replies)
        adaptive_timeout[ttl] -= 1


def flows_to_forward(g, ttl, nks):
    # Extract at max n1 flows per interface at ttl
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    flows = []
    vertices_ttl = find_vertex_by_ttl(g, ttl)
    flows_by_v = {}
    for v in vertices_ttl:
        flows_by_v[v] = []
        if mda_continue_probing_v(g, ttl, v, nks):
            v_successors = find_successors_ttl(g, v, ttl)
            # Now extract the flows that were not sent at ttl + 1
            for flow_id in ttls_flow_ids[v][ttl]:
                if flow_id in black_flows[ttl + 1]:
                    continue
                # Look if the flow has already been used.
                successor_flow_ttl_v = find_vertex_by_ttl_flow_id(g, ttl + 1, flow_id)
                if successor_flow_ttl_v is None:
                    nk_index = len(v_successors) + 1
                    if len(v_successors) == 0:
                        nk_index = 2
                    if len(flows_by_v[v]) < nks[nk_index] or len(flows_by_v[v]) == 0:
                        flows.append(flow_id)
                flows_by_v[v].append(flow_id)
    return flows

def forward_flows(g, destination, ttl, flows):
    forward_probes = [build_probe(destination, ttl + 1, flow) for flow in flows]

    # Limit the number of simultaneous probes to 150
    for i in range(0, len(forward_probes), max_batch_link_probe_size):
        if i + max_batch_link_probe_size > len(forward_probes):
            batch_forward_probes = forward_probes[i:]
        else:
            batch_forward_probes = forward_probes[i:i+max_batch_link_probe_size]
        replies, unanswered = send_probes(batch_forward_probes, default_timeout)

        update_graph_from_replies(g, replies)

        if len(replies) == 0 and len(find_vertex_by_ttl(g, ttl+1)) == 0:
            update_unanswered(unanswered, ttl + 1, True, g)
        else:
            update_unanswered(unanswered, ttl + 1, False, g)
        time.sleep(1)

# Node control returns the minimum number of flows to collect (best case)

def node_control_ttl(g, ttl, nks):
    missing_flows = 0

    vertices_ttl = find_vertex_by_ttl(g, ttl)
    flow_dist = {}
    # No need to do node control if the only vertex is a star
    ip_address = g.vertex_properties["ip_address"]
    if len(vertices_ttl) == 1 and ip_address[vertices_ttl[0]].startswith("*"):
        return 0
    for v in vertices_ttl:
        missing_flows_v = node_control_v(g, v, ttl, nks)
        flow_dist[v] = missing_flows_v
        if  missing_flows_v > 0:
            missing_flows += missing_flows_v
    return missing_flows, flow_dist

def node_control_v(g, v, ttl, nks):
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    successors_ttl = len(find_successors_ttl(g, v, ttl))
    #unresponsive flows
    u_flows = unresponsive_forwarded_flows(g, v, ttl)
    v_flows = ttls_flow_ids[v][ttl]

    available_flows = len(v_flows) - len(u_flows)

    return nks[successors_ttl + 1] - available_flows


def unresponsive_forwarded_flows(g, v, ttl):
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]

    black_flows_ttl = black_flows[ttl+1]
    return list(set(ttls_flow_ids[v][ttl]).intersection(set(black_flows_ttl)))


def stochastic_probing(g, destination, ttl, min_flows, missing_flows):
    # Find the maximum flow for this ttl
    max_flow_ttl = find_max_flow_id(g, ttl) + 1

    # Optimization here.
    if min_flows < 10:
        vertices_ttl = find_vertex_by_ttl(g, ttl)
        min_flows = min_flows * len(vertices_ttl)

    # Optimization. Compute the average number of flows to send given the measured distribution across
    # the different nodes of the ttl.
    # ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    # flow_dist = {v : len(ttls_flow_ids[v][ttl]) for v in find_vertex_by_ttl(g, ttl)}
    # total_flows = sum([len(flow_dist[v]) for v in flow_dist.keys()])
    # # Base the number to send on the worst probability basis.
    # # 1 probe has the value probability to reach v in flow_value_dist
    # flow_value_dist = {v : missing_flows[v] * float(flow_dist[v]) / total_flows}
    # # Compute the number of needed probes
    # avg_needed_probes =




    stochastic_probes = [build_probe(destination, ttl, i) for i in range(max_flow_ttl, max_flow_ttl + min_flows)]
    logging.debug("Stochastic probing. Has to at least send " + str(min_flows) + " to reach statistical guarantees.")
    replies, unanswered = send_probes(stochastic_probes, stochastic_timeout)

    update_graph_from_replies(g, replies)

    update_unanswered(unanswered, ttl, False, g)

def probe_until_nk(g, destination, ttl, nprobe_sent, hypothesis, nks):
    while nprobe_sent < nks[hypothesis]:
        next_flow_id = find_max_flow_id(g, ttl)
        nprobes = nks[hypothesis] - nprobe_sent
        # Generate the nprobes, don't use the black flows found at ttl - 1
        probes = generate_probes(nprobes, destination, ttl, next_flow_id)
        replies, unanswered = send_probes(probes, default_timeout)
        update_unanswered(unanswered, ttl, False, g)
        # Update the graph
        update_graph_from_replies(g, replies)
        # Additional stuff specific to NKs
        for probe, reply in replies:
            src_ip, flow_id, ttl_reply, ip_id_reply, mpls_infos = extract_icmp_reply_infos(reply)
            if is_new_ip(g, src_ip):
                hypothesis = hypothesis + 1

        nprobe_sent = nprobe_sent + nprobes


def stochastic_and_forward(g, destination, ttl, nks):
    # If not enough flows, do some stochastic probing and Node control.
    # If the stochastic flows are the same during N rounds, stop the ttl.
    same_consecutive_stochastic_flows = 0
    stochastic_flows, missing_flows = node_control_ttl(g, ttl, nks)
    while stochastic_flows > 0 and get_total_probe_sent() < give_up_probes:
        stochastic_probing(g, destination, ttl, stochastic_flows, missing_flows)
        next_stochastic_flows, missing_flows = node_control_ttl(g, ttl, nks)
        if stochastic_flows == next_stochastic_flows:
            same_consecutive_stochastic_flows += 1
            if same_consecutive_stochastic_flows == 30:
                break
        stochastic_flows = next_stochastic_flows

    # Then forward these flows the the subsequent hop
    flows = flows_to_forward(g, ttl, nks)
    forward_flows(g, destination, ttl, flows)


def vertices_dict_to_int_dict(d):
    int_dict = {}
    for key, values in d.items():
        int_values = set(int(v) for v in values)
        int_dict[int(key)] = int_values

    return int_dict

def int_dict_to_vertices_dict(d, g):
    vertices_dict = {}
    for key, values in d.items():
        v_values = set(g.vertex(v) for v in values)
        vertices_dict[g.vertex(key)] = v_values
    return vertices_dict
