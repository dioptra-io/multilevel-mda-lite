from Algorithm.Utils import *


def probe_until_nk_mda(g, destination, ttl, nprobe_sent, hypothesis, nks):
    while nprobe_sent < nks[hypothesis]:
        next_flow_id = find_max_flow_id(g, ttl)
        nprobes = nks[hypothesis] - nprobe_sent
        # Generate the nprobes, don't use the black flows found at ttl - 1
        probes = generate_probes(nprobes, destination, ttl, next_flow_id)
        replies, unanswered, before = send_probes(probes, default_timeout)
        if len(replies) == 0 and nprobe_sent == 0:
            update_unanswered(unanswered, ttl, True, g)
        else:
            update_unanswered(unanswered, ttl, False)
        for probe, reply in replies:
            src_ip, flow_id, ttl_reply, ip_id_reply, mpls_infos = extract_icmp_reply_infos(reply)
            ttl_probe, ip_id_probe = extract_probe_infos(probe)
            alias_result = [before, reply.time, ip_id_reply, ip_id_probe]
            if is_new_ip(g, src_ip):
                hypothesis = hypothesis + 1
            # Update the graph
            g = update_graph(g, src_ip, ttl_probe, ttl_reply, flow_id, alias_result, mpls_infos)
        nprobe_sent = nprobe_sent + nprobes

def mda(g, destination, nks):
    ip_address = g.vertex_properties["ip_address"]


    consecutive_star = 0
    error_loop_looping_ip = None
    consecutive_loop = 0
    for ttl in range (0, max_ttl):
        logging.info("Starting MDA discovery between hop " + str(ttl) + " and " + str(ttl+1))
        vertices_ttl = find_vertex_by_ttl(g, ttl)
        while mda_continue_probing_ttl(g, ttl, nks) and get_total_probe_sent() < give_up_probes:
            # If the only vertex at TTL is a star, we dont need stochastic probing. Just send some flows until reach nks.

            if len(vertices_ttl) == 1 and ip_address[vertices_ttl[0]].startswith("*"):
                # 1 for nb successor, +1 for index in table nks
                probe_until_nk_mda(g, destination, ttl+1, 0, 1+1, nks)
                break

            stochastic_and_forward(g, destination, ttl, nks)
            # Give up if the response rate is too low. This is common when configuration or routing error.
            subsequent_flows = find_flows(g, ttl+1)
            if len(black_flows[ttl+1]) * give_up_undesponsive_rate > len(subsequent_flows) > 0:
                logging.info("Response rate too low. Giving up. Can be due to routing configuration error.")
                return

        # Return if destination reached.
        only_destination = True
        vertices_successors = find_vertex_by_ttl(g, ttl + 1)

        if len(vertices_successors) == 1 :

            lone_ip = vertices_successors[0]

            if ip_address[lone_ip].startswith("*"):
                consecutive_star += 1
                if consecutive_star < default_stop_on_consecutive_stars:
                    continue
                else:
                    logging.info(str(default_stop_on_consecutive_stars) + " consecutive stars found, stopping the algorithm.")
                    return
            if  ip_address[lone_ip] == error_loop_looping_ip:
                consecutive_loop += 1
                error_loop_looping_ip = ip_address[lone_ip]
                if consecutive_loop < default_stop_on_consecutive_stars:
                    continue
                else:
                    logging.info(str(default_stop_on_consecutive_stars) + " consecutive loop found, stopping the algorithm.")
                    return
            else:
                consecutive_loop = 0
                error_loop_looping_ip = ip_address[lone_ip]
        else:
            consecutive_star = 0
            consecutive_loop = 0
            error_loop_looping_ip = None
        for v in vertices_successors:
            if ip_address[v] != destination:
                only_destination = False
                break
        if only_destination:
            return

