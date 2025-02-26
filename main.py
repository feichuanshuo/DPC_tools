"""
主界面
"""
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication
from qfluentwidgets import FluentWindow
from components.Pages.PolicyAnalysis import PAPage
from components.Pages.StaticDetect import SDPage
from components.Pages.DynamicDetect import DDPage
from components.Pages.ViolationJudge import VJPage

import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)

class Window(FluentWindow):
    """ 主界面 """

    def __init__(self):
        super().__init__()

        self.policyAnalysisInterface = PAPage(self)
        self.staticDetectInterface = SDPage(self)
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
