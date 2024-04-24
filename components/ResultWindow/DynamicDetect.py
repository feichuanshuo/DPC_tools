# 动态监测结果窗口
from PySide6.QtGui import Qt
from PySide6.QtWidgets import QWidget, QVBoxLayout,QTableWidgetItem, QStackedWidget
from qfluentwidgets import Pivot
from components import MTable

class DynamicDetect(QWidget):

    def __init__(self, data):
        super().__init__()
        self.data = data

        self.pivot = Pivot(self)
        self.stackedWidget = QStackedWidget(self)
        self.mainLayout = QVBoxLayout(self)

        # 设置窗口大小
        self.resize(1000, 600)
        self.setWindowTitle("动态检测结果")

        # 权限统计
        self.count_table = MTable(self)
        # 设置表格行数和列数
        self.count_table.setRowCount(len(self.data['count']))
        self.count_table.setColumnCount(2)
        # 设置水平表头
        self.count_table.setHorizontalHeaderLabels(['权限', '调用次数'])
        # 设置列宽
        self.count_table.setColumnWidth(0, 500)
        self.count_table.horizontalHeader().setStretchLastSection(True)
        # 设置行高
        self.count_table.verticalHeader().setDefaultSectionSize(50)
        # 设置表格内容
        for index, (key, value) in enumerate(self.data['count'].items()):
            self.count_table.setItem(index, 0, QTableWidgetItem(key))
            self.count_table.setItem(index, 1, QTableWidgetItem(str(value)))

        # 日志
        self.log_table = MTable(self)
        # 设置表格行数和列数
        self.log_table.setRowCount(len(self.data['log']))
        self.log_table.setColumnCount(6)
        # 设置水平表头
        self.log_table.setHorizontalHeaderLabels(['时间点', 'APP行为', '行为主体', '行为描述', '传入参数', '调用堆栈'])
        # 设置列宽
        self.log_table.setColumnWidth(0, 150)
        self.log_table.setColumnWidth(1, 150)
        self.log_table.setColumnWidth(2, 150)
        self.log_table.setColumnWidth(3, 200)
        self.log_table.setColumnWidth(4, 200)
        self.log_table.horizontalHeader().setStretchLastSection(True)
        # 设置表格内容
        for index, log in enumerate(self.data['log']):
            self.log_table.setItem(index, 0, QTableWidgetItem(log['alert_time']))
            self.log_table.setItem(index, 1, QTableWidgetItem(log['action']))
            self.log_table.setItem(index, 2, QTableWidgetItem(log['subject_type']))
            self.log_table.setItem(index, 3, QTableWidgetItem(log['messages']))
            self.log_table.setItem(index, 4, QTableWidgetItem(log['arg']))
            self.log_table.setItem(index, 5, QTableWidgetItem(log['stacks']))
        # 设置行高
        self.log_table.verticalHeader().setDefaultSectionSize(200)



        # 添加标签页
        self.addSubInterface(self.count_table, 'count_table', '权限统计')
        self.addSubInterface(self.log_table, 'log_table', '检测日志')

        # 连接信号并初始化当前标签页
        self.stackedWidget.currentChanged.connect(self.onCurrentIndexChanged)
        self.stackedWidget.setCurrentWidget(self.count_table)
        self.pivot.setCurrentItem(self.count_table.objectName())

        self.mainLayout.addWidget(self.pivot, 0, Qt.AlignHCenter)
        self.mainLayout.addWidget(self.stackedWidget)

    # 添加标签页
    def addSubInterface(self, widget: QWidget, object_name: str, text: str):
        widget.setObjectName(object_name)
        self.stackedWidget.addWidget(widget)

        # 使用全局唯一的 objectName 作为路由键
        self.pivot.addItem(
            routeKey=object_name,
            text=text,
            onClick=lambda: self.stackedWidget.setCurrentWidget(widget)
        )

    def onCurrentIndexChanged(self, index):
        widget = self.stackedWidget.widget(index)
        self.pivot.setCurrentItem(widget.objectName())


