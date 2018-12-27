import logging
from graph_tool.all import *



def is_mpls_alias(g, v1, v2):
    return is_mpls_interface(g, v1) and is_mpls_interface(g, v2) \
           and not is_multi_fec_mpls(g, v1) and not is_multi_fec_mpls(g, v2) \
           and has_same_mpls_label(g, v1, v2)


def is_mpls_interface(g, v):
    mpls = g.vertex_properties["mpls"]
    return len(mpls[v]) > 0


def is_multi_fec_mpls(g, v):
    mpls = g.vertex_properties["mpls"]
    mpls_infos_v = mpls[v]
    mpls_labels_v1 = set(mpls_infos_v[i]["label"] for i in range(0, len(mpls_infos_v)))

    return len(mpls_labels_v1) > 1


def has_same_mpls_label(g, v1, v2):
    mpls = g.vertex_properties["mpls"]
    ip_address = g.vertex_properties["ip_address"]
    # Look at mpls labels of both vertices
    mpls_infos_v1 = mpls[v1]
    mpls_infos_v2 = mpls[v2]
    

    label1 = mpls_infos_v1[0]
    label2 = mpls_infos_v2[0]
    if label1 == label2:
        logging.debug("Found same MPLS label : " + str(label1) + " for " + ip_address[v1] + ", " + ip_address[v2])
        return True
    else:
        return False
