from scapy.all import *

# 대상 IP 주소 설정
target_ip = "8.8.8.8"
# ICMP Echo 요청 생성
packet = IP(dst=target_ip)/ICMP()

# 패킷 전송 및 응답 수신
response = sr1(packet)
# 응답 출력
response.show()
