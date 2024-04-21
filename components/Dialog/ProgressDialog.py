from PySide6 import QtWidgets
from PySide6.QtGui import Qt
from qfluentwidgets import MessageBoxBase, SubtitleLabel, IndeterminateProgressRing



class ProgressDialog(MessageBoxBase):
    def __init__(self, parent=None, title=""):
        super().__init__(parent)
        self.title_label = SubtitleLabel(title)

        self.spinner = IndeterminateProgressRing()
        # 调整大小
        self.spinner.setFixedSize(80, 80)
        # 调整厚度
        self.spinner.setStrokeWidth(4)
        self.spinner_layout = QtWidgets.QHBoxLayout()
        self.spinner_layout.setAlignment(Qt.AlignCenter)
        self.spinner_layout.addWidget(self.spinner)



        # 将组件添加到布局中
        self.viewLayout.addWidget(self.title_label)
        # self.viewLayout.addWidget(self.spinner)
        self.viewLayout.addLayout(self.spinner_layout)

        # 设置对话框的最小宽度
        self.widget.setMinimumWidth(350)

        # 隐藏底部按钮
        self.yesButton.hide()
        self.cancelButton.hide()
        self.buttonGroup.setStyleSheet("QFrame { background-color: white; border:none;}")
        self.buttonGroup.setFixedHeight(0)
