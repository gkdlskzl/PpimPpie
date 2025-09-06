from PyQt5.QtWidgets import *
from PyQt5 import uic
import sys
import requests
import itertools
import time
import argparse


form_class = uic.loadUiType("bruteforce.ui")[0]


class WindowClass(QMainWindow, form_class) : 
    def __init__(self) :
        super().__init__()
        self.setupUi(self)

        self.stackedWidget = self.findChild(QStackedWidget, "stackedWidget")
        self.button1 = self.findChild(QPushButton, "btn2")
        self.button2 = self.findChild(QPushButton, "btn1")

        # 버튼 클릭 이벤트 연결
        self.button1.clicked.connect(self.show_page1)
        self.button2.clicked.connect(self.show_page2)
        
    def show_page1(self):
        self.stackedWidget.setCurrentIndex(0)
        
        
    def show_page2(self):
        self.stackedWidget.setCurrentIndex(1)


if __name__ == '__main__' : 
    app = QApplication(sys.argv)
    mywindow = WindowClass()
    mywindow.show()
    app.exec_()


