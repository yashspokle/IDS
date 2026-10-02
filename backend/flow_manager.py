from scapy.all import IP, IPv6, TCP, UDP
from collections import defaultdict
from feature_builder import build_features
from predictor import predict_attack
from alert_engine import create_alert
from database import save_alert

import time
import threading


FLOW_TIMEOUT = 5
MIN_PACKETS = 2

flows = defaultdict(lambda: {
    "start_time": None,
    "last_time": None,
    "packets": 0,
    "bytes": 0,
    "forward_packets": 0,
    "reverse_packets": 0,
    "forward_bytes": 0,
    "reverse_bytes": 0,
    "tcp_flags": [],
    "src_ip": None,
    "dst_ip": None,
    "src_port": None,
    "dst_port": None,
    "protocol": None,
})


flow_lock = threading.Lock()


def get_packet_info(packet):

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

    elif IPv6 in packet:
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst

    else:
        return None

    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags = str(packet[TCP].flags)

    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        flags = ""

    else:
        return None

    return src_ip, dst_ip, src_port, dst_port, protocol, flags


def finalize_flow(flow_key, flow):

    duration = flow["last_time"] - flow["start_time"]

    print("\n" + "=" * 80)
    print("FLOW COMPLETED")

    print(
        f'{flow["protocol"]} | '
        f'{flow["src_ip"]}:{flow["src_port"]} → '
        f'{flow["dst_ip"]}:{flow["dst_port"]}'
    )

    print(f'Packets: {flow["packets"]}')
    print(f'Bytes: {flow["bytes"]}')
    print(f'Duration: {duration:.2f}s')

    # Ignore extremely small flows
    if flow["packets"] < MIN_PACKETS:
        print("Skipped: insufficient packets")
        del flows[flow_key]
        return

    features = build_features(flow)

    prediction, confidence = predict_attack(features)

    print("Prediction:", prediction)
    print("Confidence:", f"{confidence * 100:.2f}%")

    alert = create_alert(
        prediction,
        confidence,
        flow["src_ip"],
        flow["dst_ip"]
    )

    print("Alert:", alert)

    save_alert(alert)

    del flows[flow_key]


def cleanup_flows():

    while True:

        time.sleep(1)

        now = time.time()

        expired = []

        with flow_lock:

            for key, flow in list(flows.items()):

                if flow["last_time"] is None:
                    continue

                idle_time = now - flow["last_time"]

                if idle_time >= FLOW_TIMEOUT:
                    expired.append((key, flow))

            for key, flow in expired:
                finalize_flow(key, flow)


def process_packet(packet):

    info = get_packet_info(packet)

    if info is None:
        return

    (
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        flags
    ) = info

    endpoint_a = (src_ip, src_port)
    endpoint_b = (dst_ip, dst_port)

    if endpoint_a <= endpoint_b:

        flow_key = (
            endpoint_a,
            endpoint_b,
            protocol
        )

        direction = "forward"

    else:

        flow_key = (
            endpoint_b,
            endpoint_a,
            protocol
        )

        direction = "reverse"

    now = time.time()

    with flow_lock:

        flow = flows[flow_key]

        # New flow
        if flow["start_time"] is None:

            flow["start_time"] = now

            flow["src_ip"] = src_ip
            flow["dst_ip"] = dst_ip
            flow["src_port"] = src_port
            flow["dst_port"] = dst_port
            flow["protocol"] = protocol

        # Update activity time
        flow["last_time"] = now

        # Update statistics
        flow["packets"] += 1
        flow["bytes"] += len(packet)

        if direction == "forward":

            flow["forward_packets"] += 1
            flow["forward_bytes"] += len(packet)

        else:

            flow["reverse_packets"] += 1
            flow["reverse_bytes"] += len(packet)

        if protocol == "TCP":
            flow["tcp_flags"].append(flags)


# Start background cleanup
cleanup_thread = threading.Thread(
    target=cleanup_flows,
    daemon=True
)

cleanup_thread.start()