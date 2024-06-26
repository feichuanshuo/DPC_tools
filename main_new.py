"""
主界面
"""
from PySide6.QtGui import Qt, QIcon
from PySide6.QtWidgets import QFrame, QHBoxLayout, QApplication
from qfluentwidgets import FluentWindow, SubtitleLabel, setFont
from components_new.Pages.DynamicDetect import DDPage

import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)


class Widget(QFrame):

    def __init__(self, text: str, parent=None):
        super().__init__(parent=parent)
        self.label = SubtitleLabel(text, self)
        self.hBoxLayout = QHBoxLayout(self)

        setFont(self.label, 24)
        self.label.setAlignment(Qt.AlignCenter)
        self.hBoxLayout.addWidget(self.label, 1, Qt.AlignCenter)

        # 必须给子界面设置全局唯一的对象名
        self.setObjectName(text.replace(' ', '-'))


class Window(FluentWindow):
    """ 主界面 """

    def __init__(self):
        super().__init__()

        # 创建子界面

        self.homeInterface = Widget('Home Interface', self)
        self.dynamicDetectInterface = DDPage(self)

        self.initNavigation()
        self.initWindow()

    def initNavigation(self):
        self.addSubInterface(self.homeInterface, QIcon('icon/static_detect.svg'), '静态检测')
        self.addSubInterface(self.dynamicDetectInterface, QIcon('icon/dynamic_detect.svg'), '动态检测')

    def initWindow(self):
        self.resize(900, 700)
        self.setWindowIcon(QIcon('icon/logo.svg'))
        self.setWindowTitle('安卓隐私合规检测工具')


if __name__ == '__main__':
    app = QApplication([])
    w = Window()
    w.show()
    app.exec()
