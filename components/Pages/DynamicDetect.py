from PySide6.QtGui import Qt
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QTableWidgetItem
from qfluentwidgets import TitleLabel, StrongBodyLabel, ScrollArea

from components import MTable
from utils.dynamic_detect.hook import FridaHook


class DDPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.fh = FridaHook(self.parent())

        self.dd_layout = QVBoxLayout(self)

        """检测结果"""
        self.result_box = QWidget()
        self.result_box.setObjectName("sd-result-box")
        self.result_box.setStyleSheet("#sd-result-box {background-color: transparent;border: none;}")
        self.result_layout = QVBoxLayout(self.result_box)
        self.result_layout.setAlignment(Qt.AlignTop)
        # 设置标题
        self.result_box_title = QWidget()
        self.result_box_title_layout = QHBoxLayout(self.result_box_title)
        self.result_box_title_layout.setAlignment(Qt.AlignCenter)
        self.result_box_title_label = TitleLabel("检测结果")
        self.result_box_title_layout.addWidget(self.result_box_title_label)
        self.result_layout.addWidget(self.result_box_title)

        # 基本信息
        self.label1 = StrongBodyLabel("基本信息")
        self.result_layout.addWidget(self.label1)
        self.result_table = MTable()
        self.result_table.setFixedHeight(105)
        # 设置行数和列数
        self.result_table.setColumnCount(2)
        self.result_table.setRowCount(2)
        # 隐藏表头
        self.result_table.horizontalHeader().hide()
        # 设置列宽
        self.result_table.setColumnWidth(0, 450)
        self.result_table.horizontalHeader().setStretchLastSection(True)
        # 设置行高
        self.result_table.verticalHeader().setDefaultSectionSize(50)
        # 设置表格内容
        self.result_table.setItem(0, 0, QTableWidgetItem("应用名称"))
        self.result_table.setItem(1, 0, QTableWidgetItem("是否有隐私政策弹窗"))
        self.result_layout.addWidget(self.result_table)

        # 不同意隐私政策时的权限使用情况
        self.label2 = StrongBodyLabel("不同意隐私政策时的权限使用情况")
        self.result_layout.addWidget(self.label2)
        # 权限统计
        self.refused_count_table = MTable(self)
        self.refused_count_table.setFixedHeight(300)
        # 设置表格行数和列数
        # self.refused_count_table.setRowCount(11)
        self.refused_count_table.setColumnCount(2)
        # 设置水平表头
        self.refused_count_table.setHorizontalHeaderLabels(['权限', '调用次数'])
        # 设置列宽
        self.refused_count_table.setColumnWidth(0, 500)
        self.refused_count_table.horizontalHeader().setStretchLastSection(True)
        # 设置行高
        self.refused_count_table.verticalHeader().setDefaultSectionSize(50)
        self.result_layout.addWidget(self.refused_count_table)

        # 同意隐私政策时的权限使用情况
        self.label3 = StrongBodyLabel("同意隐私政策时的权限使用情况")
        self.result_layout.addWidget(self.label3)
        # 权限统计
        self.accepted_count_table = MTable(self)
        self.accepted_count_table.setFixedHeight(300)
        # 设置表格行数和列数
        # self.accepted_count_table.setRowCount(11)
        self.accepted_count_table.setColumnCount(2)
        # 设置水平表头
        self.accepted_count_table.setHorizontalHeaderLabels(['权限', '调用次数'])
        # 设置列宽
        self.accepted_count_table.setColumnWidth(0, 500)
        self.accepted_count_table.horizontalHeader().setStretchLastSection(True)
        # 设置行高
        self.accepted_count_table.verticalHeader().setDefaultSectionSize(50)
        self.result_layout.addWidget(self.accepted_count_table)

        self.scroll_area = ScrollArea()
        self.scroll_area.setWidget(self.result_box)
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setObjectName("sd-scroll-area")
        self.scroll_area.setStyleSheet(
            "#sd-scroll-area {border-radius: 5px; border: 1px solid #ccc;background-color: transparent;}"
        )
        self.dd_layout.addWidget(self.scroll_area)
        self.fh.setResult.connect(self.set_result)

    # 开始动态检测
    def start_detect(self, apk_path):
        self.fh.start(apk_path)

    # 设置数据
    def set_result(self, result):
        # 基本信息
        self.result_table.setItem(0, 1, QTableWidgetItem(result['app_name']))
        self.result_table.setItem(1, 1, QTableWidgetItem(result['has_privacy_popup']))
        # 不同意隐私政策时的权限使用情况
        refused_result = result['refused_result']
        self.refused_count_table.setRowCount(len(refused_result["count"]))
        for index, (key, value) in enumerate(refused_result['count'].items()):
            self.refused_count_table.setItem(index, 0, QTableWidgetItem(key))
            self.refused_count_table.setItem(index, 1, QTableWidgetItem(str(value)))
        # 同意隐私政策时的权限使用情况
        accepted_result = result['accepted_result']
        self.accepted_count_table.setRowCount(len(accepted_result["count"]))
        for index, (key, value) in enumerate(accepted_result["count"].items()):
            self.accepted_count_table.setItem(index, 0, QTableWidgetItem(key))
            self.accepted_count_table.setItem(index, 1, QTableWidgetItem(str(value)))