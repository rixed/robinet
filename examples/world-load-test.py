#!/usr/bin/env python3
"""How much memory, and how much time, robinet takes to run the networks of
examples/world-network.py, for several sizes and load balancings.

    % examples/world-load-test.py --routers 10 50 100 150 --duration 0.5

Each network is run at --speed=max for --duration simulated seconds, with the
administration interface on, which is what the clock and the counters are read
through. Prints one tab-separated row per run:

  routers, load balancing, links, synthesizers,
  load_s: from exec to the interface answering, i.e. reading and building,
  rss_loaded_mb: resident once built,
  rss_peak_mb: the process's high-water mark,
  sim_s, run_s: simulated seconds, and the wall seconds they took,
  cpu_s: CPU time of the whole run, loading included,
  slowdown: wall seconds per simulated second,
  sent, delivered: frames the synthesizers emitted and the sinks received,
  hops: frames every router interface emitted, i.e. the forwarding work,
  hops_per_s: of it per wall second,
  pending_max: the most events the clock ever had waiting.
"""
import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def get(port, path):
    with urllib.request.urlopen("http://127.0.0.1:%d%s" % (port, path),
                                timeout=60) as r:
        return json.load(r)


def rss_kb(pid, field):
    with open("/proc/%d/status" % pid) as f:
        for line in f:
            if line.startswith(field + ":"):
                return int(line.split()[1])
    return 0


def cpu_s(pid):
    with open("/proc/%d/stat" % pid) as f:
        fields = f.read().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


def counter(props, name, direction):
    v = props.get(name)
    if not v:
        return 0
    return sum(x["value"] for x in v["values"]
               if x["params"].get("dir") == direction)


def run(robinet, doc, duration, seed):
    port = free_port()
    t0 = time.time()
    proc = subprocess.Popen(
        [robinet, "--admin=%d" % port, "--seed=%d" % seed, "--speed=max",
         "--duration=%g" % duration, doc],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        while True:
            if proc.poll() is not None:
                raise RuntimeError("robinet exited with %d" % proc.returncode)
            try:
                sims = get(port, "/api/simulations")
                break
            except OSError:
                time.sleep(0.05)
        t_loaded = time.time()
        rss_loaded = rss_kb(proc.pid, "VmRSS")
        sim_id = next(s["id"] for s in sims if s["name"] != "admin")
        pending_max = 0
        while True:
            s = get(port, "/api/simulations/%d" % sim_id)
            pending_max = max(pending_max, s["pending_events"])
            if not s["running"]:
                break
            time.sleep(0.1)
        t_done = time.time()
        rss_peak = rss_kb(proc.pid, "VmHWM")
        cpu = cpu_s(proc.pid)
        sent = delivered = hops = 0
        widgets = get(port, "/api/simulations/%d/widgets" % sim_id)
        by_id = {w["id"]: w for w in widgets}
        for w in widgets:
            parent = by_id.get(w["parent"])
            if parent is None or "packets" not in w["properties"]:
                continue
            kind = parent["device"]
            if kind not in ("router", "host", "synthesizer"):
                continue
            props = {p["name"]: p["value"] for p in get(
                port, "/api/simulations/%d/widgets/%d/properties" %
                (sim_id, w["id"]))}
            if kind == "router":
                hops += counter(props, "packets", "egress")
            elif kind == "host":
                delivered += counter(props, "packets", "ingress")
            else:
                sent += counter(props, "packets", "egress")
        return dict(load_s=t_loaded - t0, rss_loaded_mb=rss_loaded / 1024,
                    rss_peak_mb=rss_peak / 1024, sim_s=s["now"],
                    run_s=t_done - t_loaded, cpu_s=cpu,
                    sent=sent, delivered=delivered, hops=hops,
                    pending_max=pending_max)
    finally:
        proc.kill()
        proc.wait()


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--routers", type=int, nargs="+", default=[10, 50, 100, 150])
    p.add_argument("--load-balancing", nargs="+", default=["mixed"],
                   help="0-3 or mixed, see world-network.py")
    p.add_argument("--duration", type=float, default=0.5,
                   help="simulated seconds (0.5)")
    p.add_argument("--gbps", type=float, default=1.0,
                   help="rate of each synthesizer (1)")
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--robinet", default=os.path.join(HERE, "..", "robinet.opt"))
    p.add_argument("--keep", default=None,
                   help="directory to leave the documents in")
    args = p.parse_args()

    cols = ["routers", "lb", "links", "gens", "load_s", "rss_loaded_mb",
            "rss_peak_mb", "sim_s", "run_s", "cpu_s", "slowdown", "sent",
            "delivered", "hops", "hops_per_s", "pending_max"]
    print("\t".join(cols), flush=True)
    tmp = args.keep or os.environ.get("TMPDIR", "/tmp")
    for n in args.routers:
        for lb in args.load_balancing:
            doc = os.path.join(tmp, "world-%d-%s.json" % (n, lb))
            with open(doc, "w") as out:
                info = subprocess.run(
                    [sys.executable, os.path.join(HERE, "world-network.py"),
                     str(n), "--load-balancing", lb, "--gbps", str(args.gbps),
                     "--seed", str(args.seed)],
                    stdout=out, stderr=subprocess.PIPE, text=True,
                    check=True).stderr.split()
            r = run(args.robinet, doc, args.duration, args.seed)
            r.update(routers=n, lb=lb, links=int(info[2]), gens=int(info[4]),
                     slowdown=r["run_s"] / r["sim_s"],
                     hops_per_s=r["hops"] / r["run_s"])
            print("\t".join(("%.2f" % r[c]) if isinstance(r[c], float)
                            else str(r[c]) for c in cols), flush=True)
            if not args.keep:
                os.unlink(doc)


if __name__ == "__main__":
    main()
