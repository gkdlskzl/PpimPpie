import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QPushButton, QVBoxLayout, 
                           QWidget, QLabel, QFrame)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QPalette, QColor

class MinecraftButton(QPushButton):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setFixedSize(400, 40)  # 버튼 크기 고정
        self.setFont(QFont('Arial', 12))
        self.setStyleSheet("""
            QPushButton {
                background-color: rgba(128, 128, 128, 180);
                border: 2px solid #2d2d2d;
                color: white;
                text-align: center;
            }
            QPushButton:hover {
                background-color: rgba(158, 158, 158, 200);
                border: 2px solid #ffffff;
            }
            QPushButton:pressed {
                background-color: rgba(98, 98, 98, 180);
            }
        """)

class MinecraftMenu(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        
    def initUI(self):
        # 메인 위젯 설정
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        
        # 수직 레이아웃 생성
        layout = QVBoxLayout()
        layout.setSpacing(5)  # 버튼 간격 설정
        
        # 타이틀 레이블
        title = QLabel("MINECRAFT")
        title.setFont(QFont('Arial', 30, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("color: white; text-shadow: 2px 2px #000000;")
        
        # 서브타이틀 레이블
        subtitle = QLabel("JAVA EDITION")
        subtitle.setFont(QFont('Arial', 15))
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("color: yellow;")
        
        # 버튼 생성
        buttons = [
            "싱글플레이",
            "멀티플레이",
            "Minecraft Realms",
            "모드"
        ]
        
        # 레이아웃에 위젯 추가
        layout.addStretch(1)
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addSpacing(20)
        
        # 메인 버튼 추가
        for text in buttons:
            btn = MinecraftButton(text)
            layout.addWidget(btn, alignment=Qt.AlignCenter)
            layout.addSpacing(5)
        
        # 하단 버튼 레이아웃
        bottom_layout = QVBoxLayout()
        bottom_buttons = ["설정...", "게임 종료"]
        
        for text in bottom_buttons:
            btn = MinecraftButton(text)
            btn.setFixedSize(200, 40)  # 하단 버튼은 더 작게
            bottom_layout.addWidget(btn, alignment=Qt.AlignCenter)
        
        layout.addStretch(1)
        layout.addLayout(bottom_layout)
        layout.addSpacing(20)
        
        # 버전 정보 레이블
        version_label = QLabel("Minecraft 1.19/Fabric (모드 56개)")
        version_label.setStyleSheet("color: white;")
        layout.addWidget(version_label, alignment=Qt.AlignLeft)
        
        # 저작권 정보 레이블
        copyright_label = QLabel("Copyright Mojang AB. Do not distribute!")
        copyright_label.setStyleSheet("color: white;")
        layout.addWidget(copyright_label, alignment=Qt.AlignRight)
        
        main_widget.setLayout(layout)
        
        # 윈도우 설정
        self.setStyleSheet("background-color: #2d5a27;")  # 마인크래프트 배경색
        self.setGeometry(100, 100, 800, 600)
        self.setWindowTitle('Minecraft Launcher')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = MinecraftMenu()
    ex.show()
    sys.exit(app.exec_())