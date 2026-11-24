#!/usr/bin/env python3
"""Linux/root integration test using three isolated netns and raw Ethernet frames."""
import argparse
import collections
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

MARKER = b"ethmirror-integration-"
DUT_IP = "192.0.2.2"
PORT = 39001


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, **kwargs)


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    value = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while value >> 16:
        value = (value & 0xFFFF) + (value >> 16)
    return (~value) & 0xFFFF


def frames():
    dst = bytes.fromhex("020000000002")
    src = bytes.fromhex("020000000001")
    result, payloads = [], []
    for i in range(10):
        payload = MARKER + f"udp-{i:02}".encode()
        payloads.append(payload.decode())
        udp = struct.pack("!HHHH", 39000, PORT, 8 + len(payload), 0) + payload
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), i, 0,
                         64, 17, 0, socket.inet_aton("192.0.2.1"),
                         socket.inet_aton(DUT_IP))
        ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
        result.append((dst + src + b"\x08\x00" + ip + udp).ljust(60, b"\0"))
    result.append((dst + src + b"\x88\xb5" + MARKER + b"opaque").ljust(60, b"\0"))
    result.append((dst + src + b"\x81\x00\x00\x64\x88\xb5" +
                   MARKER + b"vlan100").ljust(60, b"\0"))
    return result, payloads


def worker(kind, output):
    output = Path(output)
    if kind == "send":
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sock:
            sock.bind(("src0", 0))
            for packet in frames()[0]:
                sock.send(packet)
                time.sleep(0.01)
        return
    if kind == "local":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((DUT_IP, PORT))
    else:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        sock.bind(("dst0", 0))
        # Like libpcap, restore VLAN tags stripped into skb metadata before
        # packet sockets. This checks the complete transmitted Ethernet frame.
        sock.setsockopt(263, 8, 1)  # SOL_PACKET, PACKET_AUXDATA
    sock.settimeout(0.1)
    output.with_suffix(".ready").touch()
    received = []
    deadline = time.monotonic() + 3
    with sock:
        while time.monotonic() < deadline:
            try:
                if kind == "local":
                    packet = sock.recv(65535)
                else:
                    packet, ancillary, _, _ = sock.recvmsg(65535, 1024)
                    for level, type_, data in ancillary:
                        if level == 263 and type_ == 8 and len(data) >= 20:
                            status, _, _, _, _, tci, tpid = struct.unpack("=IIIHHHH", data[:20])
                            if status & (1 << 4):  # TP_STATUS_VLAN_VALID
                                tpid = tpid if status & (1 << 6) else 0x8100
                                packet = packet[:12] + struct.pack("!HH", tpid, tci) + packet[12:]
                if MARKER in packet:
                    received.append(packet.decode() if kind == "local" else packet.hex())
            except socket.timeout:
                pass
    output.write_text(json.dumps(received))


def wait_for(predicate, description, process=None):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if predicate():
            return
        if process is not None and process.poll() is not None:
            raise RuntimeError(f"{description}: process exited with {process.returncode}")
        time.sleep(0.05)
    raise TimeoutError(description)


def integration(args):
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Run on Linux as root (requires iproute2 and network namespaces)")
    loader = str(Path(args.loader).resolve())
    script = str(Path(__file__).resolve())
    prefix = f"em{os.getpid()}"
    src, dut, dst = [prefix + x for x in ("s", "t", "d")]
    namespaces, children = [], []
    with tempfile.TemporaryDirectory(prefix="ethmirror-test-") as temp:
        temp = Path(temp)
        log_path = temp / "loader.log"
        log = log_path.open("w")
        proc = None
        try:
            for ns in (src, dut, dst):
                run("ip", "netns", "add", ns)
                namespaces.append(ns)
                run("ip", "-n", ns, "link", "set", "lo", "up")
            run("ip", "-n", src, "link", "add", "src0", "type", "veth", "peer",
                "name", "eth0", "netns", dut)
            run("ip", "-n", dut, "link", "add", "eth1", "type", "veth", "peer",
                "name", "dst0", "netns", dst)
            run("ip", "-n", src, "link", "set", "src0", "address", "02:00:00:00:00:01")
            run("ip", "-n", dut, "link", "set", "eth0", "address", "02:00:00:00:00:02")
            for ns, dev in ((src, "src0"), (dut, "eth0"), (dut, "eth1"), (dst, "dst0")):
                run("ip", "-n", ns, "link", "set", dev, "up")
            run("ip", "-n", dut, "addr", "add", DUT_IP + "/24", "dev", "eth0")
            run("ip", "-n", dst, "link", "set", "dst0", "promisc", "on")
            # Native veth XDP requires an XDP-enabled peer for its transmit path.
            # Test default uses generic XDP, independent of this driver detail.
            proc = subprocess.Popen(["ip", "netns", "exec", dut, loader,
                                     "--xdp-mode", args.xdp_mode,
                                     "--stats-interval", "1"],
                                    cwd=temp, stdout=log, stderr=log)
            children.append(proc)
            wait_for(lambda: "ready:" in log_path.read_text(), "loader ready", proc)

            # A second instance must fail, without removing the first attachment.
            second = subprocess.run(["ip", "netns", "exec", dut, loader,
                                     "--xdp-mode", args.xdp_mode],
                                    cwd=temp, text=True, capture_output=True, timeout=10)
            assert second.returncode != 0, "second instance replaced existing XDP"
            assert proc.poll() is None, "first loader stopped"
            print("PASS existing XDP is not replaced")

            def receive_and_send(label, capture):
                outputs, receivers = {}, []
                for kind, ns in [("local", dut)] + ([("capture", dst)] if capture else []):
                    output = temp / f"{label}-{kind}.json"
                    process = subprocess.Popen(["ip", "netns", "exec", ns, sys.executable,
                                                script, "--worker", kind, str(output)])
                    children.append(process)
                    receivers.append(process)
                    outputs[kind] = output
                    wait_for(output.with_suffix(".ready").exists, f"{kind} ready", process)
                run("ip", "netns", "exec", src, sys.executable, script, "--worker", "send", "unused")
                for process in receivers:
                    assert process.wait(timeout=6) == 0, "receiver failed"
                return {kind: json.loads(path.read_text()) for kind, path in outputs.items()}

            result = receive_and_send("normal", True)
            expected, payloads = frames()
            assert collections.Counter(result["local"]) == collections.Counter(payloads), result
            assert collections.Counter(result["capture"]) == collections.Counter(p.hex() for p in expected), result
            print("PASS original UDP packets reach eth0 local socket")
            print("PASS eth1 emits exactly one byte-identical copy (UDP, opaque L2, VLAN)")

            # Delete the output: clone_redirect must fail without dropping originals.
            run("ip", "-n", dut, "link", "del", "eth1")
            result = receive_and_send("missing-egress", False)
            assert collections.Counter(result["local"]) == collections.Counter(payloads), result
            print("PASS local receive continues when egress disappears")

            proc.send_signal(signal.SIGTERM)
            assert proc.wait(timeout=5) == 0, log_path.read_text()
            data = log_path.read_text()
            counters = [line for line in data.splitlines() if line.startswith("xdp_packets=")]
            values = dict(field.split("=") for field in counters[-1].split())
            assert int(values["clone_ok"]) >= 12, data
            assert int(values["clone_errors"]) >= 12, data
            assert "detached XDP and TC mirror" in data, data
            filters = run("ip", "netns", "exec", dut, "tc", "filter", "show", "dev", "eth0", "ingress").stdout
            assert "ethmirror" not in filters, filters
            links = json.loads(run("ip", "-n", dut, "-j", "link", "show", "eth0").stdout)
            assert "xdp" not in links[0], links
            print("PASS clone failure counters and SIGTERM detach")
            print(data.strip())
        except BaseException:
            print(log_path.read_text(), file=sys.stderr)
            raise
        finally:
            for child in reversed(children):
                if child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait()
            log.close()
            for ns in reversed(namespaces):
                run("ip", "netns", "del", ns)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", choices=["local", "capture", "send"])
    parser.add_argument("output", nargs="?")
    parser.add_argument("--loader", default="./ethmirror")
    parser.add_argument("--xdp-mode", choices=["skb", "native"], default="skb")
    parsed = parser.parse_args()
    if parsed.worker:
        worker(parsed.worker, parsed.output)
    else:
        integration(parsed)
