from scapy.all import sniff
from flow_manager import process_packet


def start_capture():

    print("Starting IDS flow capture...")
    print("Press CTRL+C to stop.")

    sniff(
        prn=process_packet,
        store=False
    )


if __name__ == "__main__":
    start_capture()