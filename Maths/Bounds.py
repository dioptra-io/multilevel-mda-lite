import numpy as np
import itertools

nks = [(0, 0) ,
(0, 0) , (6, 8) , (11, 15) , (16, 21) , (21, 28) ,
(27, 36) , (32, 43) , (38, 51) , (44, 58) , (50, 66) ,
(57, 74) , (63, 82) , (69, 90) , (76, 98) , (82, 106) ,
(89, 115) , (96, 123) , (103, 131) , (109, 140) , (116, 149) ,
(123, 157) , (130, 166) , (137, 174) , (144, 183) , (151, 192) ,
(159, 201) , (166, 210) , (173, 218) , (180, 227) , (188, 236) ,
(195, 245) , (202, 254) , (210, 263) , (217, 273) , (225, 282) ,
(232, 291) , (240, 300) , (247, 309) , (255, 318) , (263, 328) ,
(270, 337) , (278, 346) , (285, 356) , (293, 365) , (301, 374) ,
(309, 384) , (316, 393) , (324, 403) , (332, 412) , (340, 422) ,
(348, 431) , (356, 441) , (364, 450) , (371, 460) , (379, 469) ,
(387, 479) , (395, 489) , (403, 498) , (411, 508) , (419, 518) ,
(427, 527) , (435, 537) , (443, 547) , (452, 556) , (460, 566) ,
(468, 576) , (476, 586) , (484, 595) , (492, 605) , (500, 615) ,
(509, 625) , (517, 635) , (525, 645) , (533, 655) , (541, 664) ,
(550, 674) , (558, 684) , (566, 694) , (575, 704) , (583, 714) ,
(591, 724) , (600, 734) , (608, 744) , (616, 754) , (625, 764) ,
(633, 774) , (641, 784) , (650, 794) , (658, 804) , (667, 814) ,
(675, 825) , (684, 835) , (692, 845) , (701, 855) , (709, 865) ,
(718, 875) , (726, 885) , (735, 896) , (743, 906) , (752, 916) ,
(760, 926) , (769, 936) , (777, 947) , (786, 957) , (794, 967) ,
(803, 977) , (812, 988) , (820, 998) , (829, 1008) , (838, 1018) ,
(846, 1029) , (855, 1039) , (863, 1049) , (872, 1060) , (881, 1070) ,
(890, 1080) , (898, 1091) , (907, 1101) , (916, 1111) , (924, 1122) ,
(933, 1132) , (942, 1142) , (951, 1153) , (959, 1163) , (968, 1174) ,
(977, 1184) , (986, 1195) , (994, 1205) , (1003, 1215) , (1012, 1226) ,
(1021, 1236) , (1030, 1247) , (1039, 1257) , (1047, 1268) , (1056, 1278) ,
(1065, 1289) , (1074, 1299) , (1083, 1310) , (1092, 1320) , (1100, 1331) ,
(1109, 1341) , (1118, 1352) , (1127, 1363) , (1136, 1373) , (1145, 1384) ,
(1154, 1394) , (1163, 1405) , (1172, 1415) , (1181, 1426) , (1190, 1437) ,
(1199, 1447) , (1208, 1458) , (1217, 1468) , (1226, 1479) , (1234, 1490) ,
(1243, 1500) , (1252, 1511) , (1261, 1522) , (1270, 1532) , (1279, 1543) ,
(1288, 1554) , (1297, 1564) , (1307, 1575) , (1316, 1586) , (1325, 1596) ,
(1334, 1607) , (1343, 1618) , (1352, 1628) , (1361, 1639) , (1370, 1650) ,
(1379, 1661) , (1388, 1671) , (1397, 1682) , (1406, 1693) , (1415, 1704) ,
(1424, 1714) , (1434, 1725) , (1443, 1736) , (1452, 1747) , (1461, 1757) ,
(1470, 1768) , (1479, 1779) , (1488, 1790) , (1498, 1801) , (1507, 1811) ,
(1516, 1822) , (1525, 1833) , (1534, 1844) , (1543, 1855) , (1553, 1866) ,
(1562, 1876) , (1571, 1887) , (1580, 1898) , (1589, 1909) , (1599, 1920) ,
(1608, 1931) , (1617, 1942) , (1626, 1952) , (1635, 1963)]

def get_nks():
    nks95 = []
    nks99 = []
    for b in nks:
        nks95.append(b[0])
        nks99.append(b[1])
    return nks95, nks99


# Probability to discover a new interface given K total interfaces and
# k discovered interfaces
def probability_diagonal_transition(K, k):
    result = float(K-k) / K
    return result

# Probability to NOT discover a new interface given K total interfaces and
# k discovered interfaces
def probability_horizontal_transition(K, k):
    result = float(k) / K
    return result


def probability_space(K, nks):
    probability_space_2_d =[[None] * (nks[x] + 1) for x in range(1, K+2)]

    probability_space_2_d[1][0] = 0
    probability_space_2_d[1][1] = 1

    # Init special case k = 1
    for i in range(1, nks[2] + 1):
        if i != 1:
            probability_space_2_d[1][i] = probability_space_2_d[1][i - 1] * probability_horizontal_transition(K, 1)

    for k in range(2, K + 1):
        for i in range(k, nks[k+1] + 1):
            if k == i:
                probability_space_2_d[k][i] = probability_space_2_d[k-1][i-1] * probability_diagonal_transition(K, k-1)
            elif i > k and i <= nks[k]:
                probability_space_2_d[k][i] =\
                probability_space_2_d[k-1][i-1] * probability_diagonal_transition(K, k-1) + \
                probability_space_2_d[k][i-1] * probability_horizontal_transition(K, k)
            else:
                probability_space_2_d[k][i] = \
                    probability_space_2_d[k][i - 1] * probability_horizontal_transition(K, k)

    return probability_space_2_d


probability_space_3_d = []
# K_max the maximum of interfaces to discover
def fill_probability_space(nks, K_max = 128):
    probability_space_3_d.append([])
    probability_space_3_d.append([])
    for K in range(2, K_max + 1):
        probability_space_3_d.append(probability_space(K, nks))



# K number of interfaces to discover
# n number of probes sent
def expectation_discovered(nks, K, n):
    expectation = 0.0
    for k in range(1, K+1):
        if n <= nks[k]:
            expectation += k*probability_space_3_d[K][k][n]
    return expectation


def compute_nks(failure_probability, max_hypothesis):
    nks = np.zeros((2000, 1))

    for K in range(2, max_hypothesis):
        probability_space_2_d = np.zeros((5000, 5000))
        probability_space_2_d[1][1] = 1
        for k in range(1, K):
            found_nk = False
            for i in itertools.count():
                if i >= k:
                    # Handle the case p[1][1]
                    if probability_space_2_d[k][i] == 0:
                        probability_space_2_d[k][i] = \
                            probability_space_2_d[k][i - 1] * probability_horizontal_transition(K, k) + \
                            probability_space_2_d[k-1][i-1] * probability_diagonal_transition(K, k-1)
                        if i == nks[k + 1] and k != K -1:
                            break
                        if probability_space_2_d[k][i] <= failure_probability and i > nks[k] and  k  == K - 1:
                            nks[K] = i
                            print (K)
                            found_nk = True
                            break
            if found_nk:
                break

    return nks

if __name__ == "__main__":
    import sys
    # print nks[32][1]
    # print nks[4][1]
    # print "Test"
    # fill_probability_space(get_nks()[1], 40)
    #
    # print expectation_discovered(get_nks()[1], 4, 8)
    # print expectation_discovered(get_nks()[1], 6, 8)
    # max_hypothesis = 200
    # nks_95 = compute_nks(0.05, max_hypothesis)
    # nks_99 = compute_nks(0.01, max_hypothesis)
    # for i in range(0, max_hypothesis):
    #     sys.stdout.write("(" + str(int(nks_95[i])) + ", " + str(int(nks_99[i])) + ") , ")
    #     if i % 5 == 0:
    #         sys.stdout.write('\n')
    # sys.stdout.flush()
    from graph_tool import load_graph
    g = load_graph("resources/IMC2018/ple44.planet-lab.eu_121.185.254.1.xml")

    failure_probas = \
    {
        92 : 0.001703,
        12 : 0.001678,
        7  : 0.001701
    }

    success_proba = 1
    for v in g.vertices():
        if v.out_degree() > 1:
            success_proba *= (1 - failure_probas[v.out_degree()])

    failure_proba = 1 - success_proba
    print ("Failure probability: " + str(failure_proba))

    print (nks[50][1] + 49)