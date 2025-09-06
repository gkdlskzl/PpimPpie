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




form_class1 = uic.loadUiType("first_loading.ui")[0]
form_class2 = uic.loadUiType("key_check.ui")[0]
form_class3 = uic.loadUiType("ppimppie_title.ui")[0]

#=============================================================
class WindowClass(QMainWindow, form_class1) : 
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
class Key_check(QMainWindow, form_class2) :
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
class ppimppie_title(QMainWindow, form_class3) :
    def __init__(self):
        super().__init__()
        self.setupUi(self)

        



#=============================================================
#=============================================================

if __name__ == '__main__' : 
    app = QApplication(sys.argv)
    mywindow = WindowClass()
    mywindow.show()
    app.exec_()


