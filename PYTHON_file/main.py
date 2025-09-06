from PyQt5.QtWidgets import QApplication, QMainWindow
from ui_to_py.loadingpy import Ui_MainWindow
from ui_to_py.Key_input import Ui_Form
from PyQt5.QtCore import QTimer
import time


class MainApp(QMainWindow, Ui_MainWindow):
    def __init__(self) :
        super().__init__()
        self.setupUi(self)
        self.butn.clicked.connect(self.progress_loading)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_progress)
        self.progress = 0

    def progress_loading(self):
        self.progress = 0
        self.timer.start(100)  # 100ms마다 timeout 이벤트 발생

    def update_progress(self):
        # if self.progress == 50 :#---------------------------------
        #     time.sleep(4)
        #     self.progress += 20
        # if self.progress <= 100:
        #     self.progressBar.setValue(self.progress)
        #     self.progress += 1
        # else:#----------------------------------------------------
            self.timer.stop()
            self.KEY()

    def KEY(self) :
        self.inputkey = Key_ipnut()
        self.close()
        self.inputkey.show()

class Key_ipnut(QMainWindow, Ui_Form) :
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.lineEdit.returnPressed.connect(self.check_key)
        self.butn.clicked.connect(self.check_key)

    def check_key(self) :
        # text = self.lineEdit.toPlainText()
        text = self.lineEdit.text()
        # print(text)
        if text == "alsrl" :
            print("open")
        else : 
            print("fall")



app = QApplication([])
window = MainApp()
window.show()
app.exec_()