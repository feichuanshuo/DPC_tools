from PySide6.QtCore import Signal
from qfluentwidgets import MessageBoxBase, SubtitleLabel, StrongBodyLabel, RadioButton
from PySide6.QtWidgets import QButtonGroup, QWidget, QHBoxLayout

from utils.dynamic_detect.hook import FridaHook
from components import MTable


class DynamicDetectDialog(MessageBoxBase):

    showProgressDialog = Signal(str, bool, bool, str, str)

    def __init__(self, parent=None, app_info=None):
        super().__init__(parent)
        # 隐私协议相关数据
        self.privacy_policy_data = {
            'show_privacy_policy_dialog': False,
            'accept_privacy_policy': False,
        }
        # 应用信息
        self.app_info = app_info
        # 设置对话框的最小宽度
        self.widget.setMinimumWidth(800)

        # 设置弹窗标题
        self.title_label = SubtitleLabel("动态检测")
        self.viewLayout.addWidget(self.title_label)

        # 设置按钮
        self.yesButton.setText("开始检测")
        self.yesButton.clicked.connect(self.hook)
        self.cancelButton.setText("取消")

        # 设置弹窗内容
        self.table = MTable()
        self.viewLayout.addWidget(self.table)
        # 设置表格内容
        table_labels = [
            "是否显示隐私政策弹窗？",
            "是否同意隐私政策？",
        ]
        # 设置表格的列数
        self.table.setColumnCount(2)
        self.table.setRowCount(len(table_labels))
        # 设置列宽
        self.table.setColumnWidth(0, 300)
        self.table.horizontalHeader().setStretchLastSection(True)
        # 设置行高
        self.table.verticalHeader().setDefaultSectionSize(50)
        # 隐藏表头
        self.table.horizontalHeader().hide()

        # 创建第一个按钮组
        self.button_group_1 = QButtonGroup(self)
        self.button_group_1.setObjectName("buttonGroup1")

        # 创建第二个按钮组
        self.button_group_2 = QButtonGroup(self)
        self.button_group_2.setObjectName("buttonGroup2")

        for label in table_labels:
            row = table_labels.index(label)
            # 设置问题
            self.table.setCellWidget(row, 0, StrongBodyLabel(label))
            # 设置选项
            button_yes = RadioButton('是')
            button_no = RadioButton('否')

            # 将单选按钮添加到互斥的按钮组
            button_box = QWidget()
            button_group = self.button_group_1 if row == 0 else self.button_group_2
            button_group.addButton(button_yes, 1)
            button_group.addButton(button_no, 0)
            button_no.setChecked(True)
            button_box_layout = QHBoxLayout(button_box)
            button_box_layout.addWidget(button_yes)
            button_box_layout.addWidget(button_no)
            self.table.setCellWidget(row, 1, button_box)
            button_group.buttonClicked.connect(self.on_button_clicked)

    # 收集隐私协议数据
    def on_button_clicked(self):
        # 使用sender()方法确定哪个按钮组的按钮被点击
        button_group = self.sender()
        button_id = button_group.checkedId()
        if button_group.objectName() == "buttonGroup1":
            if button_id:
                self.privacy_policy_data['show_privacy_policy_dialog'] = True
        elif button_group.objectName() == "buttonGroup2":
            if button_id:
                self.privacy_policy_data['accept_privacy_policy'] = True


    def hook(self):
        print(self.app_info)
        fh = FridaHook(self.parent(), self.app_info)
        fh.start()


