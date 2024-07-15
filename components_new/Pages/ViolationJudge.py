from PySide6.QtCore import QSize, Signal, QThread
from PySide6.QtGui import Qt, QIcon
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout
from qfluentwidgets import HeaderCardWidget, TransparentToolButton, ProgressBar, BodyLabel, PrimaryPushButton, \
    PillToolButton

from components_new import ProgressDialog
from utils.violation_judge import violation_judge


class ViolationJudgeThread(QThread):
    """
    动态检测线程
    """
    # 定义一个信号，用于任务完成时传递结果
    return_result = Signal(dict)

    def __init__(self):
        super().__init__()

    def run(self):
        result = violation_judge()
        # 任务完成后发出信号，传递结果
        self.return_result.emit(result)


class ListItem(QWidget):
    def __init__(self, icon, title, btn_text, parent=None):
        super().__init__(parent)
        self.setFixedHeight(60)
        self.layout = QHBoxLayout(self)
        self.icon = PillToolButton(icon)
        self.icon.setCheckable(False)
        self.icon.setFixedSize(30, 30)
        self.title = BodyLabel(title)
        self.btn = PrimaryPushButton(btn_text)
        self.btn.setFixedWidth(60)
        self.layout.addWidget(self.icon)
        self.layout.addWidget(self.title)
        self.layout.addWidget(self.btn)


class StepsCard(HeaderCardWidget):
    """
    步骤卡片
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("判定进度")
        self.cardBody = QWidget()
        self.cardBodyLayout = QVBoxLayout(self.cardBody)
        self.viewLayout.addWidget(self.cardBody)

        # 步骤条
        self.stepsBox = QWidget()
        self.steps_layout = QHBoxLayout(self.stepsBox)
        self.step1_icon = TransparentToolButton(QIcon('./icon/policy_analysis.svg'))
        self.step1_icon.setIconSize(QSize(30, 30))
        self.progress_bar1 = ProgressBar()
        self.step2_icon = TransparentToolButton(QIcon('./icon/dynamic_detect.svg'))
        self.step2_icon.setIconSize(QSize(30, 30))
        self.progress_bar2 = ProgressBar()
        self.step3_icon = TransparentToolButton(QIcon('./icon/violation_judge.svg'))
        self.step3_icon.setIconSize(QSize(30, 30))
        self.steps_layout.addWidget(self.step1_icon)
        self.steps_layout.addWidget(self.progress_bar1)
        self.steps_layout.addWidget(self.step2_icon)
        self.steps_layout.addWidget(self.progress_bar2)
        self.steps_layout.addWidget(self.step3_icon)
        self.cardBodyLayout.addWidget(self.stepsBox)

        # 具体步骤
        self.step1Item = ListItem(QIcon('./icon/policy_analysis.svg'), '隐私政策分析', '跳转')
        self.step2Item = ListItem(QIcon('./icon/dynamic_detect.svg'), '动态检测', '跳转')
        self.step3Item = ListItem(QIcon('./icon/violation_judge.svg'), '违规判定', '开始')

        self.cardBodyLayout.addWidget(self.step1Item)
        self.cardBodyLayout.addWidget(self.step2Item)
        self.cardBodyLayout.addWidget(self.step3Item)


class VJPage(QWidget):
    """
    违规判定页面
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        # 必须给子界面设置全局唯一的对象名
        self.setObjectName('Violation-Judge')
        # 违规判定线程
        self.violation_judge_thread = None
        '''布局'''
        self.vj_layout = QVBoxLayout(self)
        self.vj_layout.setAlignment(Qt.AlignTop)
        '''步骤卡片'''
        self.steps_card = StepsCard()
        self.vj_layout.addWidget(self.steps_card)

        self.steps_card.step3Item.btn.clicked.connect(self.violation_judge)

    def violation_judge(self):
        # 创建进度条
        self.progress_dialog = ProgressDialog(self, "正在解析，请稍等")
        self.progress_dialog.show()
        self.violation_judge_thread = ViolationJudgeThread()
        self.violation_judge_thread.return_result.connect(self.set_result)
        self.violation_judge_thread.start()

    def set_result(self, result):

        self.progress_dialog.close()
