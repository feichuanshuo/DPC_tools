from PySide6.QtCore import QThread, Signal
from PySide6.QtGui import Qt, QIcon
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QTextBrowser, QTableWidgetItem, QFileDialog, \
    QTreeWidgetItem
from qfluentwidgets import StrongBodyLabel, CommandBar, Action, ComboBox, HeaderCardWidget, TreeWidget
from utils.static_detect import static_detect
from components import MTable, ProgressDialog


class StaticDetectThread(QThread):
    """
    静态检测线程
    """
    # 定义一个信号，用于任务完成时传递结果
    return_result = Signal(dict)
    def __init__(self, apk_path):
        super().__init__()
        self.apk_path = apk_path

    def run(self):
        result = static_detect(self.apk_path)
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
        self.tree = TreeWidget()
        # 隐藏表头
        self.tree.setHeaderHidden(True)
        self.viewLayout.addWidget(self.tree)

class SDPage(QWidget):
    """
    动态检测界面
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        # 必须给子界面设置全局唯一的对象名
        self.setObjectName('Static-Detect')
        # 动态检测线程
        self.static_detect_thread = None
        '''APK路径'''
        self.apk_path = ""
        '''采用的检测算法'''
        self.algorithm = ""
        '''布局'''
        self.sd_layout = QVBoxLayout(self)
        self.sd_layout.setAlignment(Qt.AlignTop)
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
        self.sd_layout.addWidget(self.status_bar)

        '''命令栏'''
        self.commandBar = CommandBar()
        # 图标右侧显示文本
        self.commandBar.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        # 上传 APK 动作
        self.commandBar.addAction(Action(QIcon("./icon/apk.svg"), '上传APK', triggered=self.open_apk))
        # 添加分隔符
        self.commandBar.addSeparator()
        # 开始检测按钮
        self.commandBar.addAction(Action(QIcon("./icon/start_detect.svg"), '开始检测', triggered=self.start_detect))
        self.sd_layout.addWidget(self.commandBar)

        '''APP信息卡片'''
        self.APPInfo_card = APPInfoCard()
        self.sd_layout.addWidget(self.APPInfo_card)

        '''结果卡片'''
        self.result_card = ResultCard()
        self.sd_layout.addWidget(self.result_card)

    # 打开APK文件
    def open_apk(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "选择APK文件", "", "APK Files (*.apk)")
        if file_path:
            self.apk_path = file_path
            self.app_browser.setPlainText(file_path.split("/")[-1])

    # 开始检测
    def start_detect(self):
        if self.apk_path:
            # 创建进度条
            self.progress_dialog = ProgressDialog(self, "正在检测，请稍等")
            self.progress_dialog.show()
            self.static_detect_thread = StaticDetectThread(self.apk_path)
            self.static_detect_thread.return_result.connect(self.set_result)
            self.static_detect_thread.start()
        else:
            print("请选择APK文件")

    # 设置结果
    def set_result(self, result):
        # 设置APP信息
        self.APPInfo_card.table.setItem(0, 1, QTableWidgetItem(result['APPInfo']['app_name']))
        self.APPInfo_card.table.setItem(0, 3, QTableWidgetItem(result['APPInfo']['package_name']))
        self.APPInfo_card.table.setItem(1, 1, QTableWidgetItem(result['APPInfo']['version_name']))
        self.APPInfo_card.table.setItem(1, 3, QTableWidgetItem(result['APPInfo']['target_sdk_version']))

        # 设置检测结果
        detect_result = result['DetectResult']
        for key in detect_result:
            tree_node = QTreeWidgetItem([key])
            for nkey in detect_result[key]:
                child_node = QTreeWidgetItem([nkey])
                for nnkey in detect_result[key][nkey]:
                    child_node.addChild(QTreeWidgetItem([nnkey]))
                tree_node.addChild(child_node)
            self.result_card.tree.addTopLevelItem(tree_node)
        self.progress_dialog.close()