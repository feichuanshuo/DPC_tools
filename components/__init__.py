
from PySide6.QtGui import Qt
from PySide6.QtWidgets import QHeaderView, QAbstractItemView, QHBoxLayout
from qfluentwidgets import TableWidget, MessageBoxBase, SubtitleLabel, IndeterminateProgressRing

# 自定义表格
class MTable(TableWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        # 启用边框并设置圆角
        self.setBorderVisible(True)
        self.setBorderRadius(8)
        # 设置不自动换行
        self.setWordWrap(False)
        # 隐藏垂直表头
        self.verticalHeader().hide()
        # # 设置行高
        # self.verticalHeader().setDefaultSectionSize(50)
        # 设置表格不可拖动
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Fixed)
        # 设置表格不可编辑
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # 设置表格不可选中
        self.setSelectionMode(QAbstractItemView.NoSelection)


# 进度条
class ProgressDialog(MessageBoxBase):
    def __init__(
            self,
            parent=None,
            title="",
            hide_yes_button=True,
            hide_cancel_button=True,
            yes_button_text="确定",
            cancel_button_text="取消",
    ):
        super().__init__(parent)
        self.title_label = SubtitleLabel(title)

        self.spinner = IndeterminateProgressRing()
        # 调整大小
        self.spinner.setFixedSize(80, 80)
        # 调整厚度
        self.spinner.setStrokeWidth(4)
        self.spinner_layout = QHBoxLayout()
        self.spinner_layout.setAlignment(Qt.AlignCenter)
        self.spinner_layout.addWidget(self.spinner)

        # 将组件添加到布局中
        self.viewLayout.addWidget(self.title_label)
        self.viewLayout.addLayout(self.spinner_layout)

        # 设置对话框的最小宽度
        self.widget.setMinimumWidth(350)

        # 隐藏底部按钮
        if hide_yes_button:
            self.yesButton.hide()
        else:
            self.yesButton.setText(yes_button_text)
        if hide_cancel_button:
            self.cancelButton.hide()
        else:
            self.cancelButton.setText(cancel_button_text)
        if hide_yes_button and hide_cancel_button:
            self.buttonGroup.setStyleSheet("QFrame { background-color: white; border:none;}")
            self.buttonGroup.setFixedHeight(0)
