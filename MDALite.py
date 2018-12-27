#!/usr/bin/env python
import getopt
import time
from kamene import config
from Network.Config import set_ip_version
import copy

config.Conf.load_layers.remove("x509")

###### PLATFORM RELATED SOCKETS########
import platform
if platform.system() == "Darwin":
    config.conf.use_pcap = True
    config.conf.use_dnet = True
    from kamene.all import L3dnetSocket
    config.conf.L3socket = L3dnetSocket
elif platform.system() == "Linux":
    from scapy.all import L3PacketSocket
    config.conf.L3socket = L3PacketSocket
elif platform.system() == "Windows":
    config.conf.use_pcap = True
    config.conf.use_dnet = True
    from kamene.all import L3dnetSocket
    config.conf.L3socket = L3dnetSocket

# from scapy.all import *
# from Maths.Bounds import *
# from Packets.Utils import *
# from Graph.Operations import *
# from Graph.Visualization import *
# from scapy.contrib.icmp_extensions import *
from Graph.Statistics import *
from Alias.Resolution import *
from IP2AS.ip2as import *
from Algorithm.MDALite import *
from Algorithm.MDA import *


def resolve_aliases(destination, llb, g):

    aliases = {}
    for i in range(0, default_number_mbt):
        aliases[i] = [{}, 0, 0]

    # Maintain thwo IP-ID time serie. One with no negative deltas and one with negative deltas.
    ip_ids = g.vertex_properties["ip_ids"]

    aliases_just_ip_traceroute = [{}, get_total_probe_sent(), get_total_replies()]

    # for lb in llb:
    #     # Filter the ttls where there are multiple predecessors
    #     for ttl, nint in sorted(lb.get_ttl_vertices_number().iteritems()):
    #         vertices_by_ttl = find_vertex_by_ttl(g, ttl)
    #         ###################### Use already collected IP-ID to fast discarding ##################
    #         time_series_by_vertices = {v: ip_ids[v] for v in vertices_by_ttl}
    #         estimation_stage_candidates, full_alias_candidates = pre_estimation_stage(g, time_series_by_vertices)
    #         aliases_just_ip_traceroute[0].update(estimation_stage_candidates)

    for lb in llb:
        # Filter the ttls where there are multiple predecessors
        for ttl, nint in sorted(lb.get_ttl_vertices_number().items()):
            # This commented line uses "common neighbor" heuristic to reduce the number of pairs
            # alias_candidates = find_alias_candidates(g, ttl)
            vertices_by_ttl = find_vertex_by_ttl(g, ttl)
            ###################### Use already collected IP-ID to fast discarding ##################
            time_series_by_vertices = { v : ip_ids[v] for v in vertices_by_ttl}
            estimation_stage_candidates, full_alias_candidates = pre_estimation_stage(g, time_series_by_vertices)
            aliases_just_ip_traceroute[0].update(vertices_dict_to_int_dict(estimation_stage_candidates))
            ###################### Use MIDAR alias resolution technique #####################
            # Elimination stage
            #elimination_stage_candidates, full_alias_candidates = estimation_stage(g, vertices_by_ttl, ttl, destination)
            aliases_per_round, full_alias_candidates =  elimination_stage(g, estimation_stage_candidates, full_alias_candidates,
                                                                                     ttl, destination, None, default_number_mbt)
            # Elimination stage
            # corroboration_stage_candidates, full_alias_candidates = elimination_stage(g, elimination_stage_candidates, full_alias_candidates,
            #                                                                           ttl, destination, None, default_number_mbt - min_nb_serie)
            # Do not do the corroboratino stage as the subgraphs are already small in elimination stage

            # Update what's found without adding probing.

            # Compute what's found by round
            if len(aliases_per_round) > 0:
                for i in range(0, default_number_mbt):
                    aliases[i][0].update(aliases_per_round[i][0])
                    aliases[i][1] += aliases_per_round[i][1]
                    aliases[i][2] += aliases_per_round[i][2]
            ####################### End of MIDAR #########################
    return aliases_just_ip_traceroute, aliases

def reconnect_stars(g):
    # If some vertices are discovered at a given hop with
    # a certain flow and previous or next hop is only star, reconnect it
    ttls_flow_ids = g.vertex_properties["ttls_flow_ids"]
    ip_address = g.vertex_properties["ip_address"]
    for v in g.vertices():
        if ip_address[v].startswith("*"):
            for ttl, flow_ids in ttls_flow_ids[v].items():
                max_flow_id = max(find_max_flow_id(g, ttl+1), find_max_flow_id(g, ttl-1))
                for i in range(0, max_flow_id):
                    update_graph(g, ip_address[v], ttl, -1, i, [], None)


def check_if_option(s, l, opts):
    for opt, arg in opts:
        if opt in (s, l):
            return True
    return False


def remap(previous_g, destination):
    g = init_graph(destination)
    remapping_probes = {}
    for e in previous_g.edges():
        ttl_s, ttl_t, flow_id = find_common_flow(previous_g, e)
        if ttl_s != 0 :
            if not ttl_s in remapping_probes:
                remapping_probes[ttl_s] = [flow_id]
            else:
                remapping_probes_ttl_s = remapping_probes[ttl_s]
                if flow_id not in remapping_probes_ttl_s:
                    remapping_probes_ttl_s.append(flow_id)
        if not ttl_t in  remapping_probes:
            remapping_probes[ttl_t] = [flow_id]
        else:
            remapping_probes_ttl_t = remapping_probes[ttl_t]
            if flow_id not in remapping_probes_ttl_t:
                remapping_probes_ttl_t.append(flow_id)

    for ttl, flow_ids in remapping_probes.items():
        probes = [build_probe(destination, ttl, flow_id) for flow_id in flow_ids]
        replies, unanswered, before, after = send_probes(probes, timeout = 2 * default_timeout)
        if len(replies) == 0:
            update_unanswered(unanswered, ttl, True, g)
        update_graph_from_replies(g, replies, before)
    return g, remapping_probes

def diff(old_g, g, remapping_probes):
    diffs = []
    old_ip_address = old_g.vertex_properties["ip_address"]
    ip_address = g.vertex_properties["ip_address"]
    ttls_flow_ids = old_g.vertex_properties["ttls_flow_ids"]
    # Check if every (ttl, flow) of g has the same reply than the old_g
    for v in old_g.vertices():
        # Ignore source
        if v == 0:
            continue
        for ttl, flow_ids in ttls_flow_ids[v].items():
            flows_mapping_probes = remapping_probes[ttl]
            for flow_id in flow_ids:
                new_vertices = find_vertex_by_ttl_flow_id(g, ttl, flow_id)
                if new_vertices is not None:
                    ip_addresses = [ip_address[new_v] for new_v in new_vertices]
                    if old_ip_address[v] not in ip_addresses:
                        logging.info("Change at ttl " + str(ttl)+", flow "+ str(flow_id) + ": "+ old_ip_address[v] + " -> " + str(ip_addresses))
                        diffs.append((ttl, flow_id, "ip_change"))
                else:
                    if flow_id in flows_mapping_probes:
                        logging.info(
                            "Change at ttl " + str(ttl) + ", flow " + str(flow_id) + ": " + old_ip_address[v] + " -> " +
                            "*")
                        diffs.append((ttl, flow_id, "*"))
    return diffs


def main(argv):

    origin = time.time()
    # default values
    source_name = ""
    protocol = "udp"
    total_budget = 200000
    limit_edges = 20000

    vertex_confidence = 99
    output_file = ""
    input_file = ""
    with_inference = False
    save_flows_infos = False

    with_alias_resolution = False
    with_fingerprinting = False
    with_ip2as = False
    only_alias = False
    log_level = "INFO"
    meshing_flows = default_check_meshing_flows

    # algorithm = "mda"
    algorithm = "mda-lite"
    usage = 'Usage : 3-phase-mda.py <options> <destination>\n' \
                'options : \n' \
                '-o --ofile <outputfile> (*.xml, default: draw_graph) \n' \
                '-i --ifile <inputfile> (graph_tool supported format: see https://graph-tool.skewed.de/static/doc/quickstart.html I/O section) \n' \
                '-c --vertex-confidence <vertex-confidence> (95, 99) Give the failure probability to use in the discovered topology\n' \
                '-b --edge-budget <edge-budget> (default:5000) Budget used to discover the links when there is meshing in the topology\n' \
                '-s --save-edge-flows Save in the serialized graph the which flows have discovered which interface (in case of remeasuring)\n' \
                '-S --source <source> source ip to use in the packets\n' \
                '-a --with-alias do alias resolution on load balancers found after MDA-lite\n'\
                '-A --with-ip2as do ip2as resolution\n' \
                '-F --with-fingerprinting do fingerprinting\n' \
                '-R --only-alias do only alias resolution (NOT WORKING ATM)\n'\
                '-l --log-level set the logging level (Python standard values allowed)\n'\
                '-f --meshing-flows set the number of flows to send back/forward to detect meshing (minimum is 2)\n'\
                '-m --algorithm Choose the algorithm. Possible algorithms are (mda, mda-lite)\n'\
                '-6 --ipv6 Use IPv6'
    try:
        opts, args = getopt.getopt(argv, "ho:i:c:b:sS:aAFRl:f:m:6", ["help","ofile=",
                                                                "ifile=",
                                                                "vertex-confidence=",
                                                                "edge-budget=",
                                                                "with-inference",
                                                                "save-edge-flows",
                                                                "source=",
                                                                "with-alias",
                                                                "only-alias",
                                                                "log-level",
                                                                "meshing-flows",
                                                                "algorithm",
                                                                "ipv6"])
    except getopt.GetoptError:
        print (usage)
        sys.exit(2)
    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print (usage)

            sys.exit(2)
        elif opt in ("-o", "--ofile"):
            output_file = arg
        elif opt in ("-i", "--ifile"):
            input_file = arg
        elif opt in ("-c", "--vertex-confidence"):
            vertex_confidence = int(arg)
        elif opt in ("-b", "--edge-budget"):
            limit_edges = int(arg)
        elif opt in ("-I", "--with-inference"):
            with_inference = True
        elif opt in ("-s", "--save-edge-flows"):
            if check_if_option("-S", "--source", opts):
                save_flows_infos = True
            else:
                print ("Please provide a source if you want to save flows edges")
                exit(2)
        elif opt in ("-S", "--source"):
            source_name = arg
        elif opt in ("-a", "--with-alias"):
            with_alias_resolution = True
        elif opt in ("-A", "--with-ip2as"):
            with_ip2as = True
        elif opt in ("-F", "--with-fingerprinting"):
            with_fingerprinting = True
        elif opt in ("-R", "--only-alias"):
            only_alias = True
        elif opt in ("-l", "--log-level"):
            log_level = arg
        elif opt in ("-f", "--meshing-flows"):
            meshing_flows = int(arg)
        elif opt in ("-m", "--algorithm"):
            algorithm = arg
        elif opt in ("-6", "--ipv6"):
            set_ip_version("IPv6")

    if len(args) != 1:
        print (usage)
        sys.exit(2)
    destination  = args[0]
    logging.basicConfig(filename="MDA_log.log", level=getattr(logging, log_level.upper()), filemode="w")
    logging.getLogger().addHandler(logging.StreamHandler())
    diffs = None

    ip_probes_sent = 0
    ip_useful_probes = 0
    router_probes_sent = 0
    router_useful_probes = 0
    if input_file != "":
        init_black_flows()
        # Replay a measurement with the help of the previous measure.
        previous_g = load_graph(input_file)
        # Find the destination of the previous measure and check that it matches with the current measurement
        previous_dst = previous_g.graph_properties["destination"]
        if previous_dst != destination:
            logging.error("The input file for previous measurement does not match the destination, please provide a correct one. Exiting...")
            sys.exit(1)
        g, remapping_probes = remap(previous_g, destination)
        clean_stars(g)
        reconnect_stars(g)
        diffs = diff(previous_g, g, remapping_probes)
    if diffs is None or len(diffs) > 0:

        if only_alias:
            # HACK FOR DEBUG ###
            g = load_graph("test.xml")
            llb = extract_load_balancers(g)
        else:
            init_black_flows()
            g = init_graph(destination)
            if algorithm == "mda-lite":
                mda_lite(g, destination, vertex_confidence, total_budget, limit_edges, with_inference, nk99,meshing_flows)
            elif algorithm == "mda":
                # This is a classic MDA.
                mda(g, destination, nk99)
            ip_probes_sent = get_total_probe_sent()
            ip_useful_probes = get_total_replies()
            # g = load_graph("test.xml")
            # llb = extract_load_balancers(g)
            clean_stars(g)
            reconnect_stars(g)
            remove_self_loop_destination(g, destination)
        if with_fingerprinting:
            # Get infos on fingerprinting
            echo_replies, unanswered = send_fingerprinting_probes(g)
            update_finger_printing(g, echo_replies)
        if with_alias_resolution:
            logging.info("Starting phase 4 : proceeding to alias resolution")
            #############
            #copy_g = Graph(g)
            # interfaces = copy_g.new_vertex_property("vector<string>", [])
            # copy_g.vertex_properties["interfaces"] = interfaces
            llb = extract_load_balancers(g)
            before_alias = time.time()
            int_aliases_just_ip_traceroute, int_aliases_per_round = resolve_aliases(destination, llb, g)
            print ("Duration of alias resolution : " + str(time.time() - before_alias) + " seconds")
            #r_g = router_graph(aliases, r_g)
            aliases_just_ip_traceroute = int_dict_to_vertices_dict(int_aliases_just_ip_traceroute[0], g)
            router_probes_sent = get_total_probe_sent() - ip_probes_sent
            router_useful_probes = get_total_replies() - ip_useful_probes
            save_routers_round(-1, aliases_just_ip_traceroute, int_aliases_just_ip_traceroute[1], int_aliases_just_ip_traceroute[2], g)
            # dump_routers_round(-1, g)
            for round, (int_aliases, probes_sent, replies_received) in int_aliases_per_round.items():
                aliases = int_dict_to_vertices_dict(int_aliases, g)
                save_routers_round(round, aliases, probes_sent, replies_received, g)
                # dump_routers_round(round, g)

            save_routers(int_dict_to_vertices_dict(int_aliases_per_round[default_number_mbt - 1][0], g), g)
            remove_self_loop_destination(g, destination)


        if with_ip2as:
            logging.info("Starting phase 5 : proceeding to ip2as resolution")
            #g = load_graph("router_level_test.xml")
            ripe_ip2as(g)
            # bgp_stream_ip_to_as(g, origin)

    end_time = time.time() - origin

    # Save some globals in the graphs (probes sent).

    g_ip_probes_sent = g.new_graph_property("int")
    g_ip_probes_sent[g] = ip_probes_sent
    g.graph_properties["ip_probes_sent"] = g_ip_probes_sent

    g_router_probes_sent = g.new_graph_property("int")
    g_router_probes_sent[g] = router_probes_sent
    g.graph_properties["router_probes_sent"] = g_router_probes_sent

    g_ip_useful_probes = g.new_graph_property("int")
    g_ip_useful_probes[g] = ip_useful_probes
    g.graph_properties["useful_probes"] = g_ip_useful_probes

    g_router_useful_probes = g.new_graph_property("int")
    g_router_useful_probes[g] = router_useful_probes
    g.graph_properties["useful_probes"] = g_router_useful_probes

    g_time = g.new_graph_property("double")
    g_time[g] = origin
    g.graph_properties["starting_time"] = g_time

    g_end_time = g.new_graph_property("double")
    g_end_time[g] = end_time
    g.graph_properties["end_time"] = g_end_time



    print ("Duration of measurement : " + str(end_time) + " seconds")
    print ("Found a graph with " + str(len(g.get_vertices())) + " vertices and " + str(len(g.get_edges())) + " edges")
    print ("Total probes sent for ip traceroute: " + str(ip_probes_sent))
    print ("Total replies received for ip traceroute: " + str(ip_useful_probes))
    print ("Total probes sent for alias resolution: " + str(router_probes_sent))
    print ("Total replies received for alias resolution: " + str(router_useful_probes))
    print ("Percentage of edges inferred : " + str(get_percentage_of_inferred(g)) + "%")
    print ("Phase 3 finished")


    if save_flows_infos:
        # Get source info
        source_ip = source_name
        enrich_flows(g, source_ip, destination, protocol, sport, dport)

    if output_file == "draw":
        #r_g = load_graph("router_level_test.xml")
        graph_topology_draw(g, with_alias_resolution, with_ip2as)
        # if with_alias_resolution:
        #     graph_router_topology_level_draw(r_g)
    elif output_file != "":
        g.save(output_file)
    # Dump txt results in any case
    dump_results(g, with_alias_resolution, with_ip2as, destination)

if __name__ == "__main__":

    main(sys.argv[1:])

