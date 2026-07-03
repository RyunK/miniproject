from scapy.all import *
from datetime import datetime


def parse_packet(packet):
    print("=" * 80)
    print(f"Time : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Ethernet
    if packet.haslayer(Ether):
        eth = packet[Ether]
        print("[Ethernet]")
        print(f"  Src MAC : {eth.src}")
        print(f"  Dst MAC : {eth.dst}")
        print(f"  Type    : {hex(eth.type)}")

    # IP
    if packet.haslayer(IP):
        ip = packet[IP]
        print("[IPv4]")
        print(f"  Src IP  : {ip.src}")
        print(f"  Dst IP  : {ip.dst}")
        print(f"  TTL     : {ip.ttl}")
        print(f"  Proto   : {ip.proto}")

    # IPv6
    elif packet.haslayer(IPv6):
        ip = packet[IPv6]
        print("[IPv6]")
        print(f"  Src IP  : {ip.src}")
        print(f"  Dst IP  : {ip.dst}")
        print(f"  HopLimit: {ip.hlim}")
        print(f"  NextHdr : {ip.nh}")

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

    # ICMP
    elif packet.haslayer(ICMP):
        icmp = packet[ICMP]
        print("[ICMP]")
        print(f"  Type    : {icmp.type}")
        print(f"  Code    : {icmp.code}")

    # DNS
    if packet.haslayer(DNS):
        dns = packet[DNS]
        print("[DNS]")
        print(f"  Transaction ID : {dns.id}")
        print(f"  Questions      : {dns.qdcount}")
        print(f"  Answers        : {dns.ancount}")

        if dns.qd:
            print(f"  Query          : {dns.qd.qname.decode(errors='ignore')}")

    # HTTP Payload (간단 출력)
    if packet.haslayer(Raw):
        raw = packet[Raw].load
        try:
            text = raw.decode(errors="ignore")
            if text.strip():
                print("[Payload]")
                print(text[:200])  # 최대 200바이트만 출력
        except:
            pass


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