"""
主界面
"""
from PySide6.QtGui import Qt, QIcon
from PySide6.QtWidgets import QFrame, QHBoxLayout, QApplication
from qfluentwidgets import FluentWindow, SubtitleLabel, setFont
from components_new.Pages.PolicyAnalysis import PAPage
from components_new.Pages.DynamicDetect import DDPage
from components_new.Pages.ViolationJudge import VJPage

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
        # self.policyAnalysisInterface = Widget('隐私政策分析', self)
        self.policyAnalysisInterface = PAPage(self)
        self.staticDetectInterface = Widget('Static Detect', self)
        # self.dynamicDetectInterface = Widget('动态检测', self)
        self.dynamicDetectInterface = DDPage(self)
        self.violationJudgeInterface = VJPage(self)

        self.initNavigation()
        self.initWindow()

    def initNavigation(self):
        self.addSubInterface(self.policyAnalysisInterface, QIcon('icon/policy_analysis.svg'), '隐私政策分析')
        self.addSubInterface(self.staticDetectInterface, QIcon('icon/static_detect.svg'), '静态检测')
        self.addSubInterface(self.dynamicDetectInterface, QIcon('icon/dynamic_detect.svg'), '动态检测')
        self.addSubInterface(self.violationJudgeInterface, QIcon('icon/violation_judge.svg'), '违规判定')

    def initWindow(self):
        self.resize(900, 700)
        self.setWindowIcon(QIcon('icon/logo.svg'))
        self.setWindowTitle('安卓隐私合规检测工具')


if __name__ == '__main__':
    app = QApplication([])
    w = Window()
    w.show()
    app.exec()
