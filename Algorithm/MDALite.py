from Algorithm.Utils import *
from Maths.Bounds import *
from Graph.Probabilities import *

def get_ttls_in_lb(llb):
    ttls_with_lb = []
    for lb in llb:
        for ttl in lb.get_ttl_vertices_number():
            ttls_with_lb.append(ttl)
    return ttls_with_lb

def reconnect_successors(g, destination, ttl):
    reconnect_impl(g, destination, ttl, ttl + 1)

def reconnect_predecessors(g, destination, ttl):
    reconnect_impl(g, destination, ttl, ttl-1)

def reconnect_impl(g, destination, ttl, ttl2):
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    if ttl > ttl2 :
        no_neighbors_vertices = find_no_predecessor_vertices(g, ttl)
    else:
        no_neighbors_vertices = find_no_successor_vertices(g, ttl)
    check_neighbors_probes = []
    for v in no_neighbors_vertices:
        # Find a flow that is not in black flow if possible
        candidates_flows = ttls_flow_ids[v][ttl]
        flow_id = None
        for candidate_flow in candidates_flows:
            if candidate_flow not in black_flows[ttl2]:
                flow_id = candidate_flow
                break
        if flow_id is not None:
            check_neighbors_probes.append(build_probe(destination, ttl2, flow_id))
    replies, unanswered, before = send_probes(check_neighbors_probes, default_timeout)
    update_unanswered(unanswered, ttl, False)
    update_graph_from_replies(g, replies, before)

# These functions reconnect a flow_number number of flows (serves for checking cross edges)
def reconnect_flows_ttl_predecessor(g, destination, ttl, flow_number):
    reconnect_flows_ttl_impl(g, destination, ttl, ttl - 1, flow_number)

def reconnect_flows_ttl_successor(g, destination, ttl, flow_number):
    reconnect_flows_ttl_impl(g, destination, ttl , ttl + 1, flow_number)
def reconnect_flows_ttl_impl(g, destination, ttl, ttl2, flow_number):
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    vertices_ttl = find_vertex_by_ttl(g, ttl)
    check_neighbors_probes = []
    for v in vertices_ttl:
        for i in range(1, flow_number+1):
            flow_ids_ttl = ttls_flow_ids[v][ttl]
            if len(flow_ids_ttl) >= i:
                flow_id = ttls_flow_ids[v][ttl][i - 1]
                predecessors = find_vertex_by_ttl_flow_id(g, ttl2, flow_id)
                if predecessors is None:
                    if flow_id not in black_flows[ttl2]:
                        check_neighbors_probes.append(build_probe(destination, ttl2, flow_id))
    replies, unanswered, before = send_probes(check_neighbors_probes, default_timeout)
    update_unanswered(unanswered, ttl, False)
    update_graph_from_replies(g, replies, before)

def probe_asymmetry_ttl(g, destination, lb, ttl, nprobe_sent, max_probe_needed, nks):
    while nprobe_sent < max_probe_needed:
        next_flow_id = find_max_flow_id(g, ttl)
        nprobes = max_probe_needed - nprobe_sent
        # Generate the nprobes
        probes = generate_probes(nprobes, destination, ttl, next_flow_id)
        replies, unanswered, before = send_probes(probes, default_timeout)
        update_unanswered(unanswered, ttl, False)
        update_graph_from_replies(g, replies, before)
        nprobe_sent = nprobe_sent + nprobes
        reconnect_predecessors(g, destination, ttl)
        max_probe_needed = max_probes_needed_ttl(g, lb, ttl, nks)


def execute_phase3(g, destination, llb, vertex_confidence,total_budget, limit_link_probes, with_inference, nks, meshing_flows):
    #llb : List of load balancer lb
    for lb in llb:
        # nint is the number of already discovered interfaces
        for ttl, nint in sorted(lb.get_ttl_vertices_number().items()):
            probe_until_nk(g, destination, ttl, find_probes_sent(g, ttl), nint+1, nks)
            # Check if this is a divergent ttl and if we found cross edges
            is_divergent_ttl = is_a_divergent_ttl(g, ttl)
            vertices_prev_ttl = find_vertex_by_ttl(g, ttl-1)
            vertices_next_ttl = find_vertex_by_ttl(g, ttl+1)
            if len(vertices_prev_ttl) == 1:
                # Only reconnect predecessors if we know we have only one pred at ttl-1
                reconnect_predecessors(g, destination, ttl)
            if len(vertices_next_ttl) == 1:
                reconnect_successors(g, destination, ttl)
            if len(vertices_prev_ttl) > 1:
                if is_divergent_ttl:
                    # Reconnect predecessors with a certain number of flows available in order to figure out width asymmetry
                    reconnect_flows_ttl_predecessor(g, destination, ttl, meshing_flows)
                    has_cross_edges = apply_multiple_predecessors_heuristic(g, ttl)
                    # If we find width asymmetry with no cross edges, adapt nks
                    degrees = out_degrees_ttl(g, ttl - 1)
                else:
                    reconnect_flows_ttl_successor(g, destination, ttl-1, meshing_flows)
                    has_cross_edges = apply_multiple_successors_heuristic(g, ttl-1)
                    degrees = in_degrees_ttl(g, ttl)
                if len(set(degrees)) != 1 and not has_cross_edges:
                    # Here we have to pass in a "local" mode with nk's for each node.
                    # Find the number of different interfaces discovered for each node at this ttl
                    # If the asymmetry is too high, meaning we are gonna loose a lot of probes to reach nks,
                    # do not do it
                    max_probe_needed = max_probes_needed_ttl(g, lb, ttl, nks)
                    probe_sent = find_probes_sent(g, ttl)
                    if max_probe_needed - probe_sent <= max_acceptable_asymmetry:
                        probe_asymmetry_ttl(g, destination, lb, ttl, probe_sent, max_probe_needed, nks)
                if with_inference:
                    if len(lb.get_ttl_vertices_number()) == 1:
                        apply_converging_heuristic(g, ttl, forward=True, backward=True)
                    elif ttl == max(lb.get_ttl_vertices_number().keys()):
                        apply_converging_heuristic(g, ttl, forward=True, backward=False)


    # Second step has been done previously by reconnecting two flows by divergent/convergent hop
    # to discover if a topology is asymmetric


    # Third step, try to infer the missing links if necessary from the flows we already have
    #reconnect_all_flows(g, destination, llb)

    # Fourth round, try to infer the missing links by generating new flows
    # This number is parametrable

    # If three consecutive rounds where we do not discover more edges, we stop
    links_probes_sent = 0
    responding = True
    # Optimization to tell keep in memory if a ttl has reached its statistical guarantees.
    ttl_finished = []
    meshing_round = 0

    # Prepare the map of the adaptive ICMP rates
    adaptive_icmp_rate = {}
    last_loss_fraction = {}
    adaptive_timeout = {}
    for lb in llb:
        for ttl , nint in sorted(lb.get_ttl_vertices_number().items()):
            adaptive_icmp_rate[ttl] = max_batch_link_probe_size
            last_loss_fraction[ttl] = 1.0
            adaptive_timeout[ttl] = default_meshing_link_timeout
    while   get_total_probe_sent() < give_up_probes \
            and links_probes_sent < limit_link_probes \
            and len(ttl_finished) < len(get_ttls_in_lb(llb)):
        logging.info('Meshing round ' + str(meshing_round) + ", sent " + str(total_probe_sent))
        meshing_round += 1
        # responding = False
        for lb in llb:

            # Filter the ttls where there are multiple predecessors
            for ttl, nint in sorted(lb.get_ttl_vertices_number().items()):
                # First hop of the diamond does not have to be reconnected
                if ttl in ttl_finished:
                    continue
                if ttl == min(lb.get_ttl_vertices_number().keys()):
                    logging.info("TTL " + str(ttl) + " finished. Unmeshed hop.")
                    ttl_finished.append(ttl)
                    continue
                # Check if this TTL is a divergence point or a convergence point
                #probes_sent_to_current_ttl = find_probes_sent(g, ttl)
                if is_a_divergent_ttl(g, ttl):
                    has_cross_edges = apply_multiple_predecessors_heuristic(g, ttl)
                else:
                    has_cross_edges = apply_multiple_successors_heuristic(g, ttl - 1)
                #probes_needed_to_reach_guarantees = max_probes_needed_ttl(g, lb, ttl, nks)
                has_to_probe_more = has_cross_edges
                if not mda_continue_probing_ttl(g, ttl-1, nks) or not has_cross_edges:
                    if not has_cross_edges:
                        logging.info("TTL " + str(ttl) + " finished. Unmeshed hop.")
                    ttl_finished.append(ttl)
                    has_to_probe_more = False
                if has_to_probe_more:

                    # Switch to MDA
                    while mda_continue_probing_ttl(g, ttl - 1, nks) and get_total_probe_sent() < give_up_probes:
                        stochastic_and_forward(g, destination, ttl - 1, nks)
                        subsequent_flows = find_flows(g, ttl)
                        if len(black_flows[ttl]) * give_up_undesponsive_rate > len(subsequent_flows) > 0:
                            logging.info("Response rate too low. Giving up. Can be due to routing configuration error.")
                            return
                    ttl_finished.append(ttl)

    # Final reconnection in case we have weird stuff
    for lb in llb:
        # Filter the ttls where there are multiple predecessors
        for ttl, nint in sorted(lb.get_ttl_vertices_number().items()):
            reconnect_predecessors(g, destination, ttl)
            reconnect_successors(g, destination, ttl)

    # Apply final heuristics based on symmetry to infer links
    if with_inference:
        remove_parallel_edges(g)
        for lb in llb:
            # Filter the ttls where there are multiple predecessors
            for ttl, nint in sorted(lb.get_ttl_vertices_number().items()):
                apply_symmetry_heuristic(g, ttl, 2)
    remove_parallel_edges(g)


def mda_lite(g, destination, vertex_confidence, total_budget, limit_edges, with_inference, nk99, meshing_flows):
    # 3 phases in the algorithm :
    # 1-2) hop by hop n_1 probes to discover length + position of LB
    # 3) Load balancer discovery
    logging.info("Starting MDA-Lite. Will use the 3-phase Algorithm.")
    logging.info("Starting phase 1 and 2 : finding a length to the destination and the place of the diamonds...")
    # Phase 1
    execute_phase1(g, destination, get_nks()[1])

    # graph_topology_draw(g)
    # Phase 2
    llb = extract_load_balancers(g)
    # We assume symmetry until we discover that it is not.
    # First reach the nks for this corresponding hops.
    logging.info("Starting phase 3 : finding the topology of the discovered diamonds")
    execute_phase3(g, destination, llb, vertex_confidence, total_budget, limit_edges, with_inference, nk99,
                   meshing_flows)


