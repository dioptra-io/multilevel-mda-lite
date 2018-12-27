import math
import random
from Graph.Operations import *
from graph_tool.all import *
red_color          = [1, 0, 0, 0.9]
transparent_red_color    = [1, 0, 0, 0.1]
blue_color         = [0, 0, 1, 0.9]
transparent_blue_color    = [1, 0, 0, 0.9]
green_color        = [0, 1, 0, 0.9]
transparent_green_color        = [0, 1, 0, 0.1]
black_color        = [0, 0, 0, 0.9]
transparent_black_color = [0,0,0,0.1]
cyan_color         = [0, 1, 1, 0.9]
pink_color         = [1, 0, 1, 0.9]
yellow_color       = [1, 1, 0, 0.9]
grey_color         = [0.5, 0.5, 0.5, 0.9]
purple_color       = [0.5, 0, 0.5, 0.9]
kaki_color         = [0.5, 0.5, 0, 0.9]
ocean_color        = [0, 0.5, 0.5, 0.9]
white_color        = [1,1,1, 0.9]


colors = [red_color, blue_color, green_color, cyan_color, pink_color, yellow_color, grey_color, purple_color, kaki_color, ocean_color,
          transparent_red_color, transparent_blue_color, transparent_green_color]

default_edge_color = [0.179, 0.203,0.210, 0.8]
def graph_topology_draw_with_inferred(g):
    inferred   = g.edge_properties["inferred"]
    color_edge = g.new_edge_property("vector<float>")
    for e in g.edges():
        if inferred[e]:
            color_edge[e] = blue_color
        else:
            color_edge[e] = default_edge_color
    pos = sfdp_layout(g, C=200.0, K=150)
    # pos = arf_layout(g1)
    graph_draw(g, pos=pos, vertex_text=g.vertex_properties["ip_address"]
               , vertex_font_size=1, vertex_size=2, edge_pen_width=0.2, edge_marker_size=6
               # ,aspect = 12,
               , output_size=(1500, 750), output=None
               , edge_color=color_edge
               )


def graph_topology_draw(g, with_alias_resolution, with_ip2as_resolution, output_file = None):
    ip_address = g.vertex_properties["ip_address"]

    # Manually adjust positions.
    pos = g.new_vertex_property("vector<float>")

    for v in g.vertices():
        pos[v] = [0, 0]

    for ttl in range(0, 30):
        vertices_by_ttl = find_vertex_by_ttl(g, ttl)
        x_coordinate = 100 * ttl
        y_coordinate = 0
        y_step = 8
        for i in range(0, len(vertices_by_ttl)):
            v = vertices_by_ttl[i]
            if pos[v][0] == 0 and pos[v][1] == 0:
                pos[v][0] = x_coordinate
                if i%2 == 0:
                    pos[v][1] = y_coordinate + i * y_step
                else:
                    pos[v][1] = y_coordinate - i * y_step

    # Adjust the position of the routers and draw it in cirle. The center of the cirle is a point near one interface of the router.
    # All the interface position must be point that respect the equation of the cirle.

    if with_alias_resolution:
        # First write the center of the routers.
        routers = g.graph_properties["routers"]
        for router in routers:
            center = [0, 0]
            radius = 1.5
            theta_step = 2 * math.pi / len(router)
            current_step = 0
            for v in g.vertices():
                if ip_address[v] in router:
                    if center[0] == 0 and center[1] == 0:
                        center[0] = pos[v][0] - radius
                        center[1] = pos[v][1]

                    if len(router) == 2:
                        pos[v][0] = center[0] + radius * math.cos(current_step * theta_step+math.pi/2)
                        pos[v][1] = center[1] + radius * math.sin(current_step * theta_step+math.pi/2)
                    else:
                        pos[v][0] = center[0] + radius * math.cos(current_step)
                        pos[v][1] = center[1] + radius * math.sin(current_step)
                    current_step += 1

    vertex_color = None
    if with_ip2as_resolution:
        vertex_color = g.new_vertex_property("vector<float>")

        g.vertex_properties["vertex_color"] = vertex_color
        ripe_asns = g.graph_properties["ripe_asns"]
        # Match all asn with colors
        color_by_asn = {}
        for i in range(0, len(ripe_asns)):
            if i >= len(colors):
                color_by_asn[ripe_asns[i]] = transparent_black_color
            color_by_asn[ripe_asns[i]] = colors[i]

        ripe_asns_v = g.vertex_properties["ripe_asns"]
        for v in g.vertices():
            # Take only the first asn for the color
            ripe_asns_infos = ripe_asns_v[v]
            if ripe_asns_infos is None:
                vertex_color[v] = transparent_black_color
            elif len(ripe_asns_infos) == 0 :
                vertex_color[v] = white_color
            else:
                first_asn = ripe_asns_infos[0]["asn"]
                vertex_color[v] = color_by_asn[first_asn]



    # pos = sfdp_layout(g, gamma= 0.0, mu=0.0, groups=g.vertex_properties["groups"]) #C=200.0, K=150
    # pos = arf_layout(g1)
    graph_draw(g, pos=pos
               , vertex_text=g.vertex_properties["ip_address"]
               , vertex_font_size=1, vertex_size= 4
               , vertex_fill_color = vertex_color
               , vertex_color = black_color
               , edge_pen_width=0.2, edge_marker_size=6
               # ,aspect = 12,
               , output_size=(1500, 750), output=output_file
               )

def graph_router_topology_level_draw(g):
    pos = sfdp_layout(g, C=200.0, K=150)
    # pos = arf_layout(g1)

    interfaces = g.vertex_properties["interfaces"]

    vertex_color = g.new_vertex_property("vector<float>")
    g.vertex_properties["vertex_color"] = vertex_color
    for v in g.vertices():
        if len(interfaces[v]) > 1:
            vertex_color[v] = blue_color
        else:
            vertex_color[v] = red_color
    graph_draw(g, pos=pos, vertex_text=g.vertex_properties["ip_address"]
               , vertex_font_size=1, vertex_size=2, edge_pen_width=0.2, edge_marker_size=6
               , vertex_fill_color = g.vertex_properties["vertex_color"]
               # ,aspect = 12,
               , output_size=(1500, 750), output=None
               )


if __name__ ==  "__main__":
    # g = load_graph("/Users/kevinvermeulen/PycharmProjects/stat-paris-traceroute/resources/router_survey/1/aladdin.planetlab.extranet.uni-passau.de_107.20.41.245_2018-04-15 19:32:11.480753.xml")
    # g = load_graph("/Users/kevinvermeulen/PycharmProjects/stat-paris-traceroute/resources/router_survey/1/planetlab13.net.in.tum.de_124.198.80.129_2018-04-13 09:53:47.442868.xml")
    g = load_graph(
        "/Users/kevinvermeulen/PycharmProjects/MDAPROTOTYPE/test.xml")
    ip_address = g.vertex_properties["ip_address"]
    for ttl in range(1, 30):
        v_by_ttls = find_vertex_by_ttl(g, ttl)
        ip_addresses_ttl = [ip_address[v] for v in v_by_ttls]
        print (str(ttl) +": "+ str(ip_addresses_ttl))

    graph_topology_draw(g, with_alias_resolution=False, with_ip2as_resolution=False)
