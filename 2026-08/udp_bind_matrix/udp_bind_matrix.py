#!/usr/bin/env python3
"""
UDP socket bind-conflict / REUSE / connect experiment for macOS (BSD semantics).

Two UDP sockets are opened one after another on the SAME port, with different
bind addresses and different SO_REUSEADDR / SO_REUSEPORT options. If both bind,
we send datagrams and observe single-socket delivery and (with connect) forced
cross-socket distribution. Each datagram's payload is the letter of its source
port (A, B, C, ...), so the receiving socket identifies the sender from the
packet content alone -- no port bookkeeping needed.

Two orthogonal axes drive the experiment:

  --src      source-port TOPOLOGY of the senders:
               single : one sender, fixed source port, SINGLE_PKTS packets
               dual   : two senders A and B, distinct fixed source ports
               many   : N senders, each a fresh distinct source port

  --connect  whether/how to connect(2) a receiver to a peer:
               none : neither connected (address rules pick a single socket)
               auto : nc-faithful: after the FIRST received datagram, that
                      socket connect()s to the datagram's source; later
                      fresh-source packets escape to the other socket. WHICH
                      socket connects is emergent from bind-addresses x
                      target, not a flag.

A connected UDP socket ONLY accepts datagrams whose source equals its peer,
so packets from other sources fall through to the other socket (the nc /
DNS-retry behavior). --connect auto is a no-op when --src single (a single
source cannot produce a cross-socket split).

Each socket's stat cell is labeled with the first letter that socket received
(A+, B+, C+, ...) and counts every datagram delivered to it.
NOTE: a single UDP datagram is always delivered to exactly ONE socket.
"""

import argparse
import errno
import re
import select
import socket
import subprocess
import sys
import time

PORT = 49941
REUSE_OPTS = ("none", "addr", "port", "both")
SINGLE_PKTS = 20    # packets for single topology
DUAL_PAIRS = 10     # (A,B) pairs for dual topology
MANY_SENDERS = 26   # senders for many topology (A..Z alphabet)
TIMEOUT_MS = 800           # per-scenario receipt deadline (also the auto first-datagram wait)
QUIET_MS = 150            # drain stops after this long without a receipt (bursts arrive in µs)
SELECT_POLL_S = 0.02      # select() poll granularity
BETWEEN_SCENARIO_SLEEP = 0.03   # pause between scenarios for kernel to release the shared port


def pick_free_port():
    """Return an ephemeral free UDP port (isolates concurrent runs)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def make_sock(addr, reuse):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    if reuse in ("addr", "both"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if reuse in ("port", "both"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    return sock


def try_bind(sock, addr):
    try:
        sock.bind((addr, PORT))
        return True, ""
    except OSError as e:
        return False, f"{e.errno}:{e.strerror}"


def new_sender(bind_ip="0.0.0.0"):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    sock.bind((bind_ip, 0))        # ephemeral source port
    return sock


def source_label(idx):
    """A, B, ..., Z, AA, AB, ... for source index idx."""
    label = ""
    idx += 1
    while idx > 0:
        idx -= 1
        label = chr(65 + idx % 26) + label
        idx //= 26
    return label


def send_wait(s1, s2, sender, letter, target, timeout):
    """Send one datagram whose payload is the sender's source letter (A, B,
    C, ...), then WAIT for its receipt (whichever socket got it). Because we
    never send the next packet until the current one is received, read order
    == delivery order (no queue-backlog reordering). Returns
    (receiving_socket, source_addr, received_letter) or None on timeout."""
    sender.sendto(letter.encode(), (target, PORT))
    deadline = time.time() + timeout
    while time.time() < deadline:
        ready, _, _ = select.select([s1, s2], [], [], SELECT_POLL_S)
        if not ready:
            continue
        for sock in ready:
            try:
                data, sender_addr = sock.recvfrom(2048)
                return sock, sender_addr, data.decode()
            except BlockingIOError:
                continue
    return None


def delivery(s1, s2, target, topology, connect):
    """Build senders and burst-send all packets (payload = each sender's
    source letter), then drain the receipts; the order column reflects the
    actual receipt order. Only the nc-faithful case waits for the FIRST
    datagram (to discover which socket receives it) before bursting.

    connect:
      none : never connect (pure address rules -> one socket wins)
      auto : nc-faithful: after the FIRST received datagram, that socket
             connect()s to the datagram's source; later fresh-source packets
             escape to the other socket. WHICH socket connects is emergent
             from bind-addresses x target, not a flag.
    """
    if topology == "single":
        a = new_sender()
        senders = [a]
        send_seq = [(a, "A")] * SINGLE_PKTS
    elif topology == "dual":
        a, b = new_sender(), new_sender()
        senders = [a, b]
        send_seq = [(a, "A"), (b, "B")] * DUAL_PAIRS
    else:  # many
        senders = [new_sender() for _ in range(MANY_SENDERS)]
        send_seq = [(sender, source_label(idx)) for idx, sender in enumerate(senders)]

    labels = {}                       # sock_id -> first letter that socket got
    counts = {"s1": 0, "s2": 0}
    order = []
    pinned = None                     # receiver socket connect()ed in auto mode

    def record(sock, letter):
        sock_id = "s1" if sock is s1 else "s2"
        counts[sock_id] += 1
        labels.setdefault(sock_id, letter)
        order.append(f"{letter}→{sock_id[1]}")

    # nc-faithful: pin the FIRST datagram's receiver to its source before
    # the burst, so the rest land under the post-connect rules.
    if connect == "auto" and topology != "single":
        first_receipt = send_wait(s1, s2, send_seq[0][0], send_seq[0][1],
                                  target, timeout=TIMEOUT_MS / 1000.0)
        if first_receipt:
            # The pre-sent datagram was received; keep it out of the burst
            # (on timeout it stays in the plan and is simply re-sent).
            send_seq = send_seq[1:]
            sock, sender_addr, letter = first_receipt
            record(sock, letter)
            sock.connect((target, sender_addr[1]))
            pinned = sock

    # Burst-send everything at once, then drain whatever each socket got.
    for sender, letter in send_seq:
        while True:
            try:
                sender.sendto(letter.encode(), (target, PORT))
                break
            except BlockingIOError:      # send buffer full (unlikely here)
                select.select([], [sender], [], SELECT_POLL_S)

    expected = len(send_seq)
    received = 0                       # burst receipts only; first was pre-drained
    deadline = time.time() + TIMEOUT_MS / 1000.0
    quiet_until = time.time() + QUIET_MS / 1000.0
    while (received < expected and time.time() < deadline
           and time.time() < quiet_until):
        ready, _, _ = select.select([s1, s2], [], [], SELECT_POLL_S)
        if not ready:
            continue
        for sock in ready:
            try:
                data, _ = sock.recvfrom(2048)
                record(sock, data.decode())
                received += 1
                quiet_until = time.time() + QUIET_MS / 1000.0
            except BlockingIOError:
                continue

    res = {"labels": labels, "counts": counts, "order": ",".join(order[:40])}
    if connect == "auto":
        res["connected"] = ("s1" if pinned is s1
                             else ("s2" if pinned is s2 else "none"))
    for sender in senders:
        sender.close()
    return res


def hearable(bind_addr, target):
    """Can a socket bound to bind_addr receive a datagram addressed to target?"""
    return bind_addr == "0.0.0.0" or bind_addr == target


def run_scenario(addr1, reuse1, addr2, reuse2, target, topology, connect):
    s1 = make_sock(addr1, reuse1)
    s2 = make_sock(addr2, reuse2)
    bound1, err1 = try_bind(s1, addr1)
    bound2, err2 = try_bind(s2, addr2)
    res = {"bound1": bound1, "bound2": bound2, "err1": err1, "err2": err2}

    if bound1 and bound2:
        if hearable(addr1, target) or hearable(addr2, target):
            res.update(delivery(s1, s2, target, topology, connect))
        else:
            res["skip"] = True   # no bound socket can ever hear this target

    s1.close()
    s2.close()
    time.sleep(BETWEEN_SCENARIO_SLEEP)
    return res


def fmt_cell(label, count):
    """'A+→1=10' or blank spaces when count is 0."""
    cell = f"{label}={count:>2}"
    return cell.ljust(9) if count else " " * 9


def format_row(addr1, reuse1, addr2, reuse2, res):
    base = f"{addr1:>9} {reuse1:>6} {addr2:>9} {reuse2:>6} | "
    if not res["bound1"]:
        # socket1 itself failed -> something else holds the port
        return base + "!! s1 bind failed: {}".format(res["err1"])
    if res["bound2"]:
        bind2_col = "Y"
    else:
        errno_str = res["err2"].split(":")[0]
        bind2_col = errno.errorcode.get(int(errno_str), errno_str) if errno_str else "N"
    base += f"{bind2_col:>10} | "
    if not res["bound2"]:
        return base + "  -  (skip: second not bound)"
    if res.get("skip"):
        return base + "  -  (no listener hears this target)"
    labels, counts = res["labels"], res["counts"]
    cells = (f"{fmt_cell(labels.get('s1', '?') + '+→1', counts['s1'])} | "
             f"{fmt_cell(labels.get('s2', '?') + '+→2', counts['s2'])}")
    tail = f" | {res['order']}"
    if res.get("connected"):
        # "connected" is only present for connect=auto runs, so this
        # annotation never appears on plain address-rule rows.
        pinned = ("none" if res["connected"] == "none"
                  else res["connected"][1])
        tail += f"  [auto-connected: {pinned}]"
    return base + cells + tail


def _run_capture(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              check=True).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _ips_from_ifconfig():
    return re.findall(r"inet (?:addr:)?((?:\d+\.){3}\d+)",
                      _run_capture(["/sbin/ifconfig"]))


def _ips_from_ip():
    return re.findall(r"inet (?:addr:)?((?:\d+\.){3}\d+)/",
                      _run_capture(["/sbin/ip", "-4", "addr"]))


def _ips_from_hostname():
    return re.findall(r"((?:\d+\.){3}\d+)",
                      _run_capture(["hostname", "-i"]))


def _ips_native():
    """Native Python fallbacks: gethostbyname_ex / getaddrinfo, plus the
    connect-getsockname trick for the kernel's default-route source IP."""
    ips = []
    try:
        _, _, ips = socket.gethostbyname_ex(socket.gethostname())
    except OSError:
        try:
            ips = sorted({ai[4][0] for ai in
                          socket.getaddrinfo(socket.gethostname(), None,
                                             socket.AF_INET)})
        except OSError:
            ips = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))    # sends no packets
        src_ip = sock.getsockname()[0]
        sock.close()
        if src_ip and src_ip != "0.0.0.0" and src_ip not in ips:
            ips.append(src_ip)
    except OSError:
        pass
    return ips


def local_ipv4_addrs():
    """List explicitly-assigned IPv4 addresses (no root needed), trying
    several sources in order: ifconfig -> ip -4 addr -> hostname -i ->
    native Python. Results are deduped; 0.0.0.0 is filtered."""
    addrs = []
    for fn in (_ips_from_ifconfig, _ips_from_ip,
               _ips_from_hostname, _ips_native):
        for addr in fn():
            if addr and addr != "0.0.0.0" and addr not in addrs:
                addrs.append(addr)
    return addrs


def get_targets(addrs=None):
    """Default run targets: always loopback, plus detected non-loopback (if any)."""
    if addrs is None:
        addrs = local_ipv4_addrs()
    non_loopback = [addr for addr in addrs
                    if not addr.startswith("127.")]
    targets = ["127.0.0.1"]
    if non_loopback:
        targets.append(non_loopback[0])
    return targets


CONNECT_ANNOTATION = {
    "none": "no connect -> address rules make ONE socket win (no distribution)",
    "auto": "discover-then-connect (nc): first datagram's receiver pins to that source; "
            "fresh-source packets escape to the other socket",
}


def run_matrix(target, topology, connect, only_both_up):
    addr_configs = [
        ("127.0.0.1", "127.0.0.1"),
        ("0.0.0.0", "0.0.0.0"),
        ("127.0.0.1", "0.0.0.0"),
        ("0.0.0.0", "127.0.0.1"),
    ]
    print(f"\n== target={target} | src={topology} | connect={connect} ==")
    print(f"   -- {CONNECT_ANNOTATION[connect]}")
    hdr = (f"{'addr1':>9} {'reuse1':>6} {'addr2':>9} {'reuse2':>6} | "
           f"{'b2/err':>10} | {'delivery':>22} | order")
    print(hdr)
    print("-" * len(hdr))
    for addr1, addr2 in addr_configs:
        for reuse1 in REUSE_OPTS:
            for reuse2 in REUSE_OPTS:
                res = run_scenario(addr1, reuse1, addr2, reuse2,
                                   target, topology, connect)
                if only_both_up and not (res["bound1"] and res["bound2"]):
                    continue
                print(format_row(addr1, reuse1, addr2, reuse2, res))


def main():
    parser = argparse.ArgumentParser(description="UDP bind / REUSE / connect experiment")
    parser.add_argument("--target", default=None,
                        help="destination address (default: loopback + auto-detected non-loopback)")
    parser.add_argument("--port", type=int, default=None,
                        help="UDP port (default: a fresh random free port to isolate concurrent runs)")
    parser.add_argument("--src", choices=["single", "dual", "many"], default="many",
                        help="sender source-port topology")
    parser.add_argument("--connect", choices=["none", "auto"], default=None,
                        help="connect policy: 'none' or nc-faithful 'auto'; default sweeps both")
    parser.add_argument("--only-both-up", action="store_true")
    args = parser.parse_args()

    global PORT
    PORT = args.port if args.port else pick_free_port()

    # connect policy to run: explicit flag -> just that one; else sweep both
    if args.connect is not None:
        connect_policies = [args.connect]
    elif args.src == "single":
        connect_policies = ["none"]  # single source: auto-connect is moot
    else:
        connect_policies = ["none", "auto"]

    # targets: explicit flag -> just that one; else loopback + detected
    if args.target:
        targets = [args.target]
    else:
        local_addrs = local_ipv4_addrs()
        targets = get_targets(local_addrs)
        print(f"[auto] available IPv4: {local_addrs}")

    sweep_note = " (connect sweep)" if len(connect_policies) > 1 else ""
    print(f"OS: {sys.platform} | port={PORT} | src={args.src}{sweep_note}")

    for target in targets:
        target_note = ("non-loopback: only 0.0.0.0 sockets hear it"
                       if target != "127.0.0.1"
                       else "loopback: 127.0.0.1 sockets hear it")
        print(f"\n########## TARGET {target}  ({target_note}) ##########")
        for connect in connect_policies:
            run_matrix(target, args.src, connect, args.only_both_up)


if __name__ == "__main__":
    main()
