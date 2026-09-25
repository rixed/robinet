#!/usr/bin/env python3
"""Write a robinet document of N routers at real places, wired roughly as a
backbone would be, and about N/10 synthesizers sending UDP to all of them.

    % examples/world-network.py 50 > /tmp/world-50.json
    % robinet --speed=max --duration=0.1 /tmp/world-50.json

Cities are taken in order of importance, so that the ten first cover every
continent and each larger network adds regional routers around them. Every
router is cabled to its nearest neighbours, the hubs among them also to the
nearest other hubs, and whatever is left disconnected to the closest router
already joined.

Every router i has:
  - one port per link, each a /30 out of 10.2.0.0/16;
  - a stub port with a host, standing for the network 10.1.i.0/24 behind it:
    the router is 10.1.i.253/30 and the host 10.1.i.254/30 on that port, and
    the whole /24 is routed via the host, which takes all of it;
  - on every tenth router, a port with a synthesizer on it, 10.4.i.0/24.

The synthesizers each send UDP, under the address of their router's host, to
random addresses of every 10.1.0.0/16 network with random ports and payload
sizes, at --gbps on average, over a 10Gbps adapter. A host answers any UDP it
is given with a port unreachable, whoever it was for, so a small ICMP comes
back to the sending side's host for every packet, along the same routes.

Routes to every other router's /24 are computed from shortest paths over the
cable lengths. A router is given every neighbour that is strictly closer to the
destination than itself, up to --paths of them, the best first: that is loop
free whatever the routers pick among them, which is what the load balancing
then decides.
"""
import argparse
import heapq
import json
import math
import random
import sys

# Name, latitude, longitude, hub. Ordered by importance, hubs spread over the
# continents first.
CITIES = [
    ("new-york", 40.7128, -74.0060, True),
    ("london", 51.5074, -0.1278, True),
    ("frankfurt", 50.1109, 8.6821, True),
    ("tokyo", 35.6762, 139.6503, True),
    ("singapore", 1.3521, 103.8198, True),
    ("los-angeles", 34.0522, -118.2437, True),
    ("sao-paulo", -23.5505, -46.6333, True),
    ("mumbai", 19.0760, 72.8777, True),
    ("sydney", -33.8688, 151.2093, True),
    ("johannesburg", -26.2041, 28.0473, True),
    ("amsterdam", 52.3676, 4.9041, True),
    ("paris", 48.8566, 2.3522, True),
    ("ashburn", 39.0438, -77.4874, True),
    ("chicago", 41.8781, -87.6298, True),
    ("dallas", 32.7767, -96.7970, True),
    ("hong-kong", 22.3193, 114.1694, True),
    ("seoul", 37.5665, 126.9780, False),
    ("marseille", 43.2965, 5.3698, True),
    ("miami", 25.7617, -80.1918, True),
    ("san-jose", 37.3382, -121.8863, True),
    ("seattle", 47.6062, -122.3321, False),
    ("madrid", 40.4168, -3.7038, False),
    ("milan", 45.4642, 9.1900, False),
    ("stockholm", 59.3293, 18.0686, False),
    ("warsaw", 52.2297, 21.0122, False),
    ("istanbul", 41.0082, 28.9784, False),
    ("dubai", 25.2048, 55.2708, True),
    ("cairo", 30.0444, 31.2357, False),
    ("lagos", 6.5244, 3.3792, False),
    ("nairobi", -1.2921, 36.8219, False),
    ("moscow", 55.7558, 37.6173, False),
    ("toronto", 43.6532, -79.3832, False),
    ("montreal", 45.5017, -73.5673, False),
    ("denver", 39.7392, -104.9903, False),
    ("atlanta", 33.7490, -84.3880, False),
    ("mexico-city", 19.4326, -99.1332, False),
    ("bogota", 4.7110, -74.0721, False),
    ("buenos-aires", -34.6037, -58.3816, False),
    ("santiago", -33.4489, -70.6693, False),
    ("lima", -12.0464, -77.0428, False),
    ("osaka", 34.6937, 135.5023, False),
    ("taipei", 25.0330, 121.5654, False),
    ("shanghai", 31.2304, 121.4737, False),
    ("beijing", 39.9042, 116.4074, False),
    ("jakarta", -6.2088, 106.8456, False),
    ("bangkok", 13.7563, 100.5018, False),
    ("chennai", 13.0827, 80.2707, False),
    ("delhi", 28.7041, 77.1025, False),
    ("melbourne", -37.8136, 144.9631, False),
    ("auckland", -36.8485, 174.7633, False),
    ("vienna", 48.2082, 16.3738, False),
    ("zurich", 47.3769, 8.5417, False),
    ("brussels", 50.8503, 4.3517, False),
    ("dublin", 53.3498, -6.2603, False),
    ("lisbon", 38.7223, -9.1393, False),
    ("copenhagen", 55.6761, 12.5683, False),
    ("oslo", 59.9139, 10.7522, False),
    ("helsinki", 60.1699, 24.9384, False),
    ("prague", 50.0755, 14.4378, False),
    ("budapest", 47.4979, 19.0402, False),
    ("bucharest", 44.4268, 26.1025, False),
    ("athens", 37.9838, 23.7275, False),
    ("rome", 41.9028, 12.4964, False),
    ("barcelona", 41.3851, 2.1734, False),
    ("munich", 48.1351, 11.5820, False),
    ("berlin", 52.5200, 13.4050, False),
    ("hamburg", 53.5511, 9.9937, False),
    ("manchester", 53.4808, -2.2426, False),
    ("kyiv", 50.4501, 30.5234, False),
    ("tel-aviv", 32.0853, 34.7818, False),
    ("riyadh", 24.7136, 46.6753, False),
    ("karachi", 24.8607, 67.0011, False),
    ("bangalore", 12.9716, 77.5946, False),
    ("kuala-lumpur", 3.1390, 101.6869, False),
    ("manila", 14.5995, 120.9842, False),
    ("ho-chi-minh", 10.8231, 106.6297, False),
    ("guangzhou", 23.1291, 113.2644, False),
    ("perth", -31.9505, 115.8605, False),
    ("brisbane", -27.4698, 153.0251, False),
    ("vancouver", 49.2827, -123.1207, False),
    ("phoenix", 33.4484, -112.0740, False),
    ("houston", 29.7604, -95.3698, False),
    ("boston", 42.3601, -71.0589, False),
    ("philadelphia", 39.9526, -75.1652, False),
    ("kansas-city", 39.0997, -94.5786, False),
    ("minneapolis", 44.9778, -93.2650, False),
    ("salt-lake-city", 40.7608, -111.8910, False),
    ("portland", 45.5152, -122.6784, False),
    ("las-vegas", 36.1699, -115.1398, False),
    ("san-diego", 32.7157, -117.1611, False),
    ("charlotte", 35.2271, -80.8431, False),
    ("nashville", 36.1627, -86.7816, False),
    ("detroit", 42.3314, -83.0458, False),
    ("pittsburgh", 40.4406, -79.9959, False),
    ("st-louis", 38.6270, -90.1994, False),
    ("new-orleans", 29.9511, -90.0715, False),
    ("calgary", 51.0447, -114.0719, False),
    ("winnipeg", 49.8951, -97.1384, False),
    ("halifax", 44.6488, -63.5752, False),
    ("panama", 8.9824, -79.5199, False),
    ("caracas", 10.4806, -66.9036, False),
    ("quito", -0.1807, -78.4678, False),
    ("rio-de-janeiro", -22.9068, -43.1729, False),
    ("fortaleza", -3.7319, -38.5267, False),
    ("porto-alegre", -30.0346, -51.2177, False),
    ("montevideo", -34.9011, -56.1645, False),
    ("cape-town", -33.9249, 18.4241, False),
    ("durban", -29.8587, 31.0218, False),
    ("accra", 5.6037, -0.1870, False),
    ("dakar", 14.7167, -17.4677, False),
    ("casablanca", 33.5731, -7.5898, False),
    ("algiers", 36.7538, 3.0588, False),
    ("tunis", 36.8065, 10.1815, False),
    ("addis-ababa", 8.9806, 38.7578, False),
    ("dar-es-salaam", -6.7924, 39.2083, False),
    ("kinshasa", -4.4419, 15.2663, False),
    ("luanda", -8.8390, 13.2894, False),
    ("djibouti", 11.5721, 43.1456, False),
    ("muscat", 23.5880, 58.3829, False),
    ("doha", 25.2854, 51.5310, False),
    ("tehran", 35.6892, 51.3890, False),
    ("baku", 40.4093, 49.8671, False),
    ("tbilisi", 41.7151, 44.8271, False),
    ("almaty", 43.2220, 76.8512, False),
    ("tashkent", 41.2995, 69.2401, False),
    ("novosibirsk", 55.0084, 82.9357, False),
    ("yekaterinburg", 56.8389, 60.6057, False),
    ("st-petersburg", 59.9311, 30.3609, False),
    ("riga", 56.9496, 24.1052, False),
    ("vilnius", 54.6872, 25.2797, False),
    ("sofia", 42.6977, 23.3219, False),
    ("belgrade", 44.7866, 20.4489, False),
    ("zagreb", 45.8150, 15.9819, False),
    ("lyon", 45.7640, 4.8357, False),
    ("bordeaux", 44.8378, -0.5792, False),
    ("porto", 41.1579, -8.6291, False),
    ("edinburgh", 55.9533, -3.1883, False),
    ("kolkata", 22.5726, 88.3639, False),
    ("hyderabad", 17.3850, 78.4867, False),
    ("dhaka", 23.8103, 90.4125, False),
    ("colombo", 6.9271, 79.8612, False),
    ("yangon", 16.8409, 96.1735, False),
    ("hanoi", 21.0278, 105.8342, False),
    ("shenzhen", 22.5431, 114.0579, False),
    ("chengdu", 30.5728, 104.0668, False),
    ("wuhan", 30.5928, 114.3055, False),
    ("busan", 35.1796, 129.0756, False),
    ("fukuoka", 33.5904, 130.4017, False),
    ("sapporo", 43.0618, 141.3545, False),
    ("vladivostok", 43.1332, 131.9113, False),
    ("guam", 13.4443, 144.7937, False),
    ("honolulu", 21.3069, -157.8583, False),
    ("anchorage", 61.2181, -149.9003, False),
    ("adelaide", -34.9285, 138.6007, False),
    ("wellington", -41.2865, 174.7762, False),
    ("port-moresby", -9.4438, 147.1803, False),
    ("suva", -18.1248, 178.4501, False),
]

# Ethernet speed numbers, as docs/simulation.md has them.
SPEED_10G, SPEED_40G, SPEED_100G = 5, 7, 8


def distance(a, b):
    """Great-circle distance in meters."""
    (_, la1, lo1, _), (_, la2, lo2, _) = a, b
    la1, lo1, la2, lo2 = map(math.radians, (la1, lo1, la2, lo2))
    h = (math.sin((la2 - la1) / 2) ** 2 +
         math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2)
    return 2 * 6371000 * math.asin(math.sqrt(h))


def build_links(cities, neighbours, hub_neighbours):
    n = len(cities)
    d = [[distance(cities[i], cities[j]) for j in range(n)] for i in range(n)]
    links = set()

    def link(i, j):
        if i != j:
            links.add((min(i, j), max(i, j)))

    for i in range(n):
        others = sorted((j for j in range(n) if j != i), key=lambda j: d[i][j])
        for j in others[:neighbours]:
            link(i, j)
        if cities[i][3]:
            hubs = [j for j in others if cities[j][3]]
            for j in hubs[:hub_neighbours]:
                link(i, j)
    # Join the islands to the closest router already joined.
    adj = {i: set() for i in range(n)}
    for i, j in links:
        adj[i].add(j)
        adj[j].add(i)
    seen, todo = {0}, [0]
    while True:
        while todo:
            i = todo.pop()
            for j in adj[i] - seen:
                seen.add(j)
                todo.append(j)
        if len(seen) == n:
            break
        i, j = min(((i, j) for i in seen for j in range(n) if j not in seen),
                   key=lambda p: d[p[0]][p[1]])
        link(i, j)
        adj[i].add(j)
        adj[j].add(i)
        seen.add(j)
        todo.append(j)
    return sorted(links), d


def shortest(n, adj, d, dst):
    """Distance from every router to [dst] along the cables."""
    dist = [math.inf] * n
    dist[dst] = 0
    heap = [(0, dst)]
    while heap:
        c, i = heapq.heappop(heap)
        if c > dist[i]:
            continue
        for j in adj[i]:
            if c + d[i][j] < dist[j]:
                dist[j] = c + d[i][j]
                heapq.heappush(heap, (dist[j], j))
    return dist


def ip(net, i):
    """The i-th address of a /16 given as its two first bytes."""
    return "%s.%d.%d" % (net, i // 256, i % 256)


def route(dst, output=None, via=None, input_port=None):
    return {"input port": input_port, "src mask": None, "dst mask": dst,
            "ip proto": None, "src port": None, "dst port": None,
            "output port": output, "via": via}


def mac(kind, i, port):
    return "02:%02x:%02x:%02x:%02x:%02x" % (
        kind, i >> 8, i & 0xff, port >> 8, port & 0xff)


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("routers", type=int)
    p.add_argument("--neighbours", type=int, default=3,
                   help="links to the nearest routers (3)")
    p.add_argument("--hub-neighbours", type=int, default=3,
                   help="links from a hub to the nearest other hubs (3)")
    p.add_argument("--paths", type=int, default=3,
                   help="next hops a router is given per destination (3)")
    p.add_argument("--load-balancing", default="mixed",
                   help="0-3 for all routers, or 'mixed' for a random one each")
    p.add_argument("--generators", type=int, default=None,
                   help="how many synthesizers (N/10, at least 1)")
    p.add_argument("--gbps", type=float, default=1.0,
                   help="average rate of each synthesizer (1)")
    p.add_argument("--stop-after", type=int, default=None,
                   help="frames each synthesizer sends (forever)")
    p.add_argument("--seed", type=int, default=0)
    args = p.parse_args()

    n = args.routers
    if not 2 <= n <= min(len(CITIES), 255):
        sys.exit("between 2 and %d routers" % min(len(CITIES), 255))
    rnd = random.Random(args.seed)
    cities = CITIES[:n]
    links, d = build_links(cities, args.neighbours, args.hub_neighbours)
    n_gens = args.generators or max(1, round(n / 10))
    gen_at = [round(k * n / n_gens) for k in range(n_gens)]

    # Ports: links first, in the order of [links], then the stub, then the
    # synthesizer if any.
    ports = {i: [] for i in range(n)}  # (neighbour, link index)
    adj = {i: set() for i in range(n)}
    for k, (i, j) in enumerate(links):
        ports[i].append((j, k))
        ports[j].append((i, k))
        adj[i].add(j)
        adj[j].add(i)

    def link_addr(k, i):
        a, b = links[k]
        return ip("10.2", 4 * k + (1 if i == a else 2))

    def port_to(i, j):
        return next(p for p, (o, _) in enumerate(ports[i]) if o == j)

    dists = [shortest(n, adj, d, t) for t in range(n)]

    def speed(i, j):
        return SPEED_100G if cities[i][3] and cities[j][3] else SPEED_10G

    devices = []
    for i, (name, lat, lon, hub) in enumerate(cities):
        stub = len(ports[i])
        gen = stub + 1 if i in gen_at else None
        nports = stub + 1 + (gen is not None)
        routes = []
        props = {}
        for p, (j, k) in enumerate(ports[i]):
            routes.append(route(link_addr(k, i) + "/30", input_port=p))
            props["#%d" % p] = {"speeds": [speed(i, j)],
                                "accept gratuitous ARP": True}
        routes.append(route("10.1.%d.253/30" % i, input_port=stub))
        props["#%d" % stub] = {"speeds": [SPEED_10G],
                               "accept gratuitous ARP": True}
        if gen is not None:
            routes.append(route("10.4.%d.1/24" % i, input_port=gen))
            props["#%d" % gen] = {"speeds": [SPEED_10G]}
        routes.append(route("10.1.%d.0/24" % i, output=stub,
                            via="10.1.%d.254" % i))
        for t in range(n):
            if t == i:
                continue
            here = dists[t][i]
            downhill = sorted(
                (d[i][j] + dists[t][j], j) for j in adj[i] if dists[t][j] < here)
            for _, j in downhill[:args.paths]:
                k = ports[i][port_to(i, j)][1]
                routes.append(route("10.1.%d.0/24" % t, output=port_to(i, j),
                                    via=link_addr(k, j)))
        lb = (rnd.randrange(4) if args.load_balancing == "mixed"
              else int(args.load_balancing))
        props[""] = {"routes": routes, "load balancing": lb,
                     "errors probability": 0.0}
        # Routes first, so that the interfaces have their addresses before
        # anything else is said to them.
        props = {"": props.pop(""), **props}
        devices.append({
            "type": "router", "path": name, "at": {"lat": lat, "lon": lon},
            "params": {"ports": nports, "speeds": [SPEED_10G, SPEED_100G],
                       "MACs": ",".join(mac(1, i, p) for p in range(nports))},
            "properties": props})
        devices.append({
            "type": "host", "path": name + "-sink",
            "at": {"lat": lat, "lon": lon},
            "params": {"static-ip": "10.1.%d.254" % i,
                       "netmask": "255.255.255.252",
                       "gateway": "10.1.%d.253" % i,
                       "MAC": mac(2, i, 0)},
            "properties": {"eth": {"speeds": [SPEED_10G]}}})
        devices.append({
            "type": "cable", "path": name + "-stub",
            "params": {"from": name, "to": name + "-sink",
                       "from port": stub, "length": 100.0}})
        if gen is not None:
            # Frames of 64 to 1400 bytes of payload, 774 on average with their
            # headers, spaced so as to average [gbps] on a 10Gbps link.
            mean_bits = (732 + 42) * 8
            gap = max(0, int(mean_bits * (10.0 / args.gbps - 1)))
            devices.append({
                "type": "synthesizer", "path": name + "-gen",
                "at": {"lat": lat, "lon": lon},
                "params": {"adapters": 1, "speeds": [SPEED_10G]},
                "properties": {"": {
                    "generators": [
                        {"name": "dst", "generator": {"uniform": {
                            "from": (10 << 24) | (1 << 16),
                            "up to (excluded)": (10 << 24) | (1 << 16) | (n << 8)}}},
                        {"name": "sport", "generator": {"uniform": {
                            "from": 1024, "up to (excluded)": 65536}}},
                        {"name": "dport", "generator": {"uniform": {
                            "from": 1, "up to (excluded)": 1024}}},
                        {"name": "size", "generator": {"uniform": {
                            "from": 64, "up to (excluded)": 1401}}},
                        {"name": "gap", "generator": {"uniform": {
                            "from": 0, "up to (excluded)": 2 * gap + 1}}}],
                    "stream": {"stop after": args.stop_after, "distance": {"gen": "gap"},
                               "distance from end": True},
                    "packet": [
                        {"name": "Eth", "fields": {
                            "source": {"const": mac(3, i, 0)},
                            "destination": {"const": mac(1, i, gen)},
                            "protocol": None, "payload": None}},
                        {"name": "Ip", "fields": {
                            "type of service": None, "total length": None,
                            "id": None, "don't fragment": {"const": True},
                            "more fragments": None, "fragment offset": None,
                            "time to live": None, "protocol": None,
                            "source": {"const": "10.1.%d.254" % i},
                            "destination": {"gen": "dst"},
                            "options": None, "payload": None}},
                        {"name": "Udp", "fields": {
                            "source port": {"gen": "sport"},
                            "destination port": {"gen": "dport"},
                            "length": None, "checksum": None,
                            "payload": None}},
                        {"name": "Data", "fields": {"gen": "size"}}],
                    "independent": False,
                    "emitting": True}}})
            devices.append({
                "type": "cable", "path": name + "-feed",
                "params": {"from": name + "-gen", "to": name,
                           "to port": gen, "length": 100.0}})
    for k, (i, j) in enumerate(links):
        devices.append({
            "type": "cable", "path": "%s-%s" % (cities[i][0], cities[j][0]),
            "params": {"from": cities[i][0], "to": cities[j][0],
                       "from port": port_to(i, j), "to port": port_to(j, i)}})

    startup = [{"path": dev["path"], "action": "power on"} for dev in devices]
    # Announce every router address, so that no packet waits for an ARP
    # exchange; the synthesizers start with the rest, at time zero, and their
    # first frames arrive after these.
    startup += [{"path": c[0], "action": "emit gratuitous ARP"} for c in cities]
    startup += [{"path": c[0] + "-sink/eth", "action": "emit gratuitous ARP"}
                for c in cities]

    doc = {"version": 1, "name": "world-%d" % n, "devices": devices,
           "startup": startup}
    json.dump(doc, sys.stdout, indent=1)
    sys.stdout.write("\n")
    print("%d routers, %d links, %d synthesizers at %s, %d route rows" % (
        n, len(links), n_gens, ", ".join(cities[g][0] for g in gen_at),
        sum(len(dev["properties"][""]["routes"]) for dev in devices
            if dev["type"] == "router")), file=sys.stderr)


if __name__ == "__main__":
    main()
