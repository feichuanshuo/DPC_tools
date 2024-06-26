from PySide6.QtCore import QThread, Signal
from PySide6.QtGui import Qt, QIcon
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QTextBrowser, QFileDialog, QTableWidgetItem
from qfluentwidgets import CommandBar, Action, ComboBox, StrongBodyLabel, HeaderCardWidget
from components_new import MTable, ProgressDialog
from utils.automator import dynamic_detect
import time


class DynamicDetectThread(QThread):
    """
    动态检测线程
    """
    # 定义一个信号，用于任务完成时传递结果
    return_result = Signal(dict)

    def __init__(self, apk_path, algorithm, N):
        super().__init__()
        self.apk_path = apk_path
        self.algorithm = algorithm
        self.N = N

    def run(self):
        result = dynamic_detect(self.apk_path, self.algorithm, self.N)
        # 任务完成后发出信号，传递结果
        self.return_result.emit(result)


class APPInfoCard(HeaderCardWidget):
    """
    APP信息卡片
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("APP信息")
        self.setFixedHeight(210)
        self.table = MTable()
        # 设置表格行列数
        self.table.setRowCount(2)
        self.table.setColumnCount(4)
        # 设置隐藏表头
        self.table.horizontalHeader().hide()
        # 设置列宽
        self.table.setColumnWidth(0, 150)
        self.table.setColumnWidth(1, 200)
        self.table.setColumnWidth(2, 150)
        self.table.horizontalHeader().setStretchLastSection(True)
        # 设置行高
        self.table.verticalHeader().setDefaultSectionSize(50)
        # 设置表格内容
        self.table.setItem(0, 0, QTableWidgetItem('APP名称'))
        self.table.setItem(0, 2, QTableWidgetItem('包名'))
        self.table.setItem(1, 0, QTableWidgetItem('版本名称'))
        self.table.setItem(1, 2, QTableWidgetItem('目标SDK版本'))

        self.viewLayout.addWidget(self.table)


class ResultCard(HeaderCardWidget):
    """
    结果卡片
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("检测结果")


class DDPage(QWidget):
    """
    动态检测界面
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        # 必须给子界面设置全局唯一的对象名
        self.setObjectName('Dynamic-Detect')
        # 动态检测线程
        self.dynamic_detect_thread = None
        '''APK路径'''
        self.apk_path = ""
        '''采用的检测算法'''
        self.algorithm = ""
        '''布局'''
        self.dd_layout = QVBoxLayout(self)
        self.dd_layout.setAlignment(Qt.AlignTop)
        '''状态栏'''
        self.status_bar = QWidget()
        self.status_bar.setFixedHeight(50)
        self.status_bar_layout = QHBoxLayout(self.status_bar)
        self.status_bar_layout.setAlignment(Qt.AlignLeft)
        # 提示标签
        self.label1 = StrongBodyLabel("当前APK：")
        self.label1.setFixedWidth(80)
        self.label1.setFixedHeight(30)
        # 显示APK名
        self.app_browser = QTextBrowser()
        self.app_browser.setFixedHeight(30)
        self.app_browser.setFixedWidth(400)
        # 将组件添加到布局
        self.status_bar_layout.addWidget(self.label1)
        self.status_bar_layout.addWidget(self.app_browser)
        self.dd_layout.addWidget(self.status_bar)

        '''命令栏'''
        self.commandBar = CommandBar()
        # 图标右侧显示文本
        self.commandBar.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        # 上传 APK 动作
        self.commandBar.addAction(Action(QIcon("./icon/apk.svg"), '上传APK', triggered=self.open_apk))
        # 添加分隔符
        self.commandBar.addSeparator()
        # 连接设备动作
        self.commandBar.addAction(Action(QIcon("./icon/USB.svg"), '连接设备'))
        # 添加分隔符
        self.commandBar.addSeparator()
        # 选择检测算法
        self.algorithm_comboBox = ComboBox()
        self.algorithm_comboBox.setPlaceholderText("选择动态检测算法")
        self.algorithm_comboBox.addItem('随机算法', userData='random')
        self.algorithm_comboBox.addItem('QLearn算法', userData='q_learn')
        self.algorithm_comboBox.addItem('SAC算法', userData='sac')
        self.algorithm_comboBox.setCurrentIndex(-1)
        # 当前选项的索引改变信号
        self.algorithm_comboBox.currentIndexChanged.connect(self.select_algorithm)
        self.commandBar.addWidget(self.algorithm_comboBox)
        # 开始检测按钮
        self.commandBar.addAction(Action(QIcon("./icon/start_detect.svg"), '开始检测', triggered=self.start_detect))
        self.dd_layout.addWidget(self.commandBar)

        '''APP信息卡片'''
        self.APPInfo_card = APPInfoCard()
        self.dd_layout.addWidget(self.APPInfo_card)

        '''结果卡片'''
        self.result_card = ResultCard()
        self.dd_layout.addWidget(self.result_card)

    # 打开APK文件
    def open_apk(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "选择APK文件", "", "APK Files (*.apk)")
        if file_path:
            self.apk_path = file_path
            self.app_browser.setPlainText(file_path.split("/")[-1])

    # 选择检测算法
    def select_algorithm(self):
        self.algorithm = self.algorithm_comboBox.currentData()
        print(self.algorithm)

    # 开始检测
    def start_detect(self):
        if self.apk_path and self.algorithm:
            # 创建进度条
            self.progress_dialog = ProgressDialog(self.parent().parent(), "正在检测，请稍等")
            self.progress_dialog.show()
            self.dynamic_detect_thread = DynamicDetectThread(self.apk_path, self.algorithm, 10)
            self.dynamic_detect_thread.return_result.connect(self.set_result)
            self.dynamic_detect_thread.start()
        else:
            print("请选择APK文件和检测算法")

    # 设置结果
    def set_result(self, result):
        self.APPInfo_card.table.setItem(0, 1, QTableWidgetItem(result['APPInfo']['app_name']))
        self.APPInfo_card.table.setItem(0, 3, QTableWidgetItem(result['APPInfo']['package_name']))
        self.APPInfo_card.table.setItem(1, 1, QTableWidgetItem(result['APPInfo']['version_name']))
        self.APPInfo_card.table.setItem(1, 3, QTableWidgetItem(result['APPInfo']['target_sdk_version']))
        self.progress_dialog.close()