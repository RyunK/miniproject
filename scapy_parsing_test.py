from scapy.all import sniff
from scapy.layers.inet import TCP, UDP

from datetime import datetime


def parse_packet(packet):
    print("=" * 80)
    print(f"Time : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # TCP
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        print("[TCP]")
        print(f"  Src Port: {tcp.sport}")
        print(f"  Dst Port: {tcp.dport}")
        print(f"  Seq     : {tcp.seq}")
        print(f"  Ack     : {tcp.ack}")
        print(f"  Flags   : {tcp.flags}")

    # UDP
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        print("[UDP]")
        print(f"  Src Port: {udp.sport}")
        print(f"  Dst Port: {udp.dport}")
        print(f"  Length  : {udp.len}")



def main():
    print("패킷 캡처 시작 (Ctrl+C로 종료)")

    try:
        sniff(
            prn=parse_packet,
            store=False
        )
    except KeyboardInterrupt:
        print("\n사용자에 의해 종료되었습니다.")


if __name__ == "__main__":
    main()