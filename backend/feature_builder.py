def get_service(src_port, dst_port):

    services = {
        20: "ftp",
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "domain",
        80: "http",
        110: "pop3",
        143: "imap4",
        443: "https",
        587: "smtp",
        993: "imap4",
        995: "pop3",
    }

    # Prefer destination port
    if dst_port in services:
        return services[dst_port]

    # If packet is server -> client, use source port
    if src_port in services:
        return services[src_port]

    return "unknown"


def get_tcp_flag(flags):

    if not flags:
        return "SF"

    flags = str(flags)

    if "R" in flags:
        return "REJ"

    if "S" in flags and "A" not in flags:
        return "S0"

    if "F" in flags:
        return "SF"

    if "A" in flags:
        return "SF"

    return "SF"


def build_features(flow):

    duration = flow["last_time"] - flow["start_time"]

    packets = flow["packets"]

    forward_packets = flow["forward_packets"]
    reverse_packets = flow["reverse_packets"]

    forward_bytes = flow["forward_bytes"]
    reverse_bytes = flow["reverse_bytes"]

    total_bytes = flow["bytes"]

    if packets > 0:
        reverse_ratio = reverse_packets / packets
    else:
        reverse_ratio = 0

    if total_bytes > 0:
        forward_ratio = forward_bytes / total_bytes
    else:
        forward_ratio = 0

    flags = flow["tcp_flags"]

    last_flag = flags[-1] if flags else ""

    tcp_flag = get_tcp_flag(last_flag)

    service = get_service(
        flow["src_port"],
        flow["dst_port"]
    )

    features = {

        "duration": duration,

        "protocol_type": flow["protocol"],

        "service": service,

        "flag": tcp_flag,

        "src_bytes": forward_bytes,

        "dst_bytes": reverse_bytes,

        "land": int(
            flow["src_ip"] == flow["dst_ip"]
        ),

        "wrong_fragment": 0,

        "urgent": 0,

        "hot": 0,

        "num_failed_logins": 0,

        "logged_in": 0,

        "num_compromised": 0,

        "root_shell": 0,

        "su_attempted": 0,

        "num_root": 0,

        "num_file_creations": 0,

        "num_shells": 0,

        "num_access_files": 0,

        "num_outbound_cmds": 0,

        "is_host_login": 0,

        "is_guest_login": 0,

        "count": packets,

        "srv_count": packets,

        "serror_rate": (
            1 if tcp_flag == "S0" else 0
        ),

        "srv_serror_rate": (
            1 if tcp_flag == "S0" else 0
        ),

        "rerror_rate": (
            1 if tcp_flag == "REJ" else 0
        ),

        "srv_rerror_rate": (
            1 if tcp_flag == "REJ" else 0
        ),

        "same_srv_rate": forward_ratio,

        "diff_srv_rate": 1 - forward_ratio,

        "srv_diff_host_rate": reverse_ratio,

        "dst_host_count": 1,

        "dst_host_srv_count": packets,

        "dst_host_same_srv_rate": forward_ratio,

        "dst_host_diff_srv_rate": 1 - forward_ratio,

        "dst_host_same_src_port_rate": forward_ratio,

        "dst_host_srv_diff_host_rate": reverse_ratio,

        "dst_host_serror_rate": (
            1 if tcp_flag == "S0" else 0
        ),

        "dst_host_srv_serror_rate": (
            1 if tcp_flag == "S0" else 0
        ),

        "dst_host_rerror_rate": (
            1 if tcp_flag == "REJ" else 0
        ),

        "dst_host_srv_rerror_rate": (
            1 if tcp_flag == "REJ" else 0
        ),
    }

    return features