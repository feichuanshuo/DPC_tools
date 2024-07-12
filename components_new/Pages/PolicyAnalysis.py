from PySide6.QtCore import QThread, Signal
from PySide6.QtGui import Qt, QIcon
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QTextBrowser, QFileDialog, QTableWidgetItem
from qfluentwidgets import StrongBodyLabel, CommandBar, Action, HeaderCardWidget

from components_new import MTable, ProgressDialog
from utils.policy_analysis import policy_analysis


class PolicyAnalysisThread(QThread):
    """
    动态检测线程
    """
    # 定义一个信号，用于任务完成时传递结果
    return_result = Signal(dict)

    def __init__(self, policy_path):
        super().__init__()
        self.policy_path = policy_path

    def run(self):
        result = policy_analysis(self.policy_path)
        # 任务完成后发出信号，传递结果
        self.return_result.emit(result)


class ResultCard(HeaderCardWidget):
    """
    结果卡片
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("检测结果")
        self.table = MTable()
        # 设置表格行列数
        self.table.setRowCount(26)
        self.table.setColumnCount(3)
        # 设置隐藏表头
        self.table.setHorizontalHeaderLabels(['隐私政策种类', '合规规则', '是否包含'])
        # 设置列宽
        self.table.setColumnWidth(0, 100)
        self.table.setColumnWidth(1, 500)
        self.table.horizontalHeader().setStretchLastSection(True)
        # 设置行高
        self.table.verticalHeader().setDefaultSectionSize(50)
        # 设置表格内容
        self.table.setItem(0, 0, QTableWidgetItem('PC1'))
        self.table.setItem(0, 1, QTableWidgetItem('CR1 隐私政策更新/生效时通知'))
        self.table.setItem(1, 1, QTableWidgetItem('CR2 告知隐私政策适用于哪些产品/服务'))
        self.table.setItem(2, 0, QTableWidgetItem('PC2'))
        self.table.setItem(2, 1, QTableWidgetItem('CR3 告知个人信息使用者的身份'))
        self.table.setItem(3, 1, QTableWidgetItem('CR4 告知如何联系个人信息使用者'))
        self.table.setItem(4, 0, QTableWidgetItem('PC3'))
        self.table.setItem(4, 1, QTableWidgetItem('CR5 收集14岁以下未成年人个人信息需征得监护人同意'))
        self.table.setItem(5, 0, QTableWidgetItem('PC4'))
        self.table.setItem(5, 1, QTableWidgetItem('CR6 在收集个人信息之前获得对隐私政策的同意'))
        self.table.setItem(6, 1, QTableWidgetItem('CR7 提供隐私政策重大变更通知'))
        self.table.setItem(7, 1, QTableWidgetItem('CR8 告知如何撤回同意'))
        self.table.setItem(8, 1, QTableWidgetItem('CR9（有条件）告知如何禁用个性化显示'))
        self.table.setItem(9, 1, QTableWidgetItem('CR10 告知PI主体的其他权利，如删除、注销等。'))
        self.table.setItem(10, 0, QTableWidgetItem('PC5'))
        self.table.setItem(10, 1, QTableWidgetItem('CR11 告知收集目的'))
        self.table.setItem(11, 1, QTableWidgetItem('CR12（可选）告知应用提供的个性化展示服务'))
        self.table.setItem(12, 1, QTableWidgetItem('CR13 告知应用程序收集哪些个人信息'))
        self.table.setItem(13, 1, QTableWidgetItem('CR14 告知个人信息的保留期限'))
        self.table.setItem(14, 1, QTableWidgetItem('CR15 告知个人信息保护措施'))
        self.table.setItem(15, 1, QTableWidgetItem('CR16（有条件）提供敏感个人信息收集的特别提醒'))
        self.table.setItem(16, 1, QTableWidgetItem('CR17 发生个人信息安全事件时及时通知'))
        self.table.setItem(17, 0, QTableWidgetItem('PC6'))
        self.table.setItem(17, 1, QTableWidgetItem('CR18（可选）通知第三方共享个人信息'))
        self.table.setItem(18, 1, QTableWidgetItem('CR19（有条件）共享个人信息时获得同意'))
        self.table.setItem(19, 1, QTableWidgetItem('CR20（有条件）告知第三方信息'))
        self.table.setItem(20, 1, QTableWidgetItem('CR21（有条件）告知分享目的'))
        self.table.setItem(21, 1, QTableWidgetItem('CR22（有条件）告知应用程序共享哪些个人信息'))
        self.table.setItem(22, 0, QTableWidgetItem('PC7'))
        self.table.setItem(22, 1, QTableWidgetItem('CR23（可选）通知跨境传输'))
        self.table.setItem(23, 1, QTableWidgetItem('CR24（有条件）如需跨境传输需征得同意'))
        self.table.setItem(24, 1, QTableWidgetItem('CR25（有条件）告知跨境传输目的'))
        self.table.setItem(25, 1, QTableWidgetItem('CR26（有条件）告知跨境传输的保护措施'))
        self.viewLayout.addWidget(self.table)


class PAPage(QWidget):
    """
    隐私政策解析界面
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        # 必须给子界面设置全局唯一的对象名
        self.setObjectName('Policy-Analysis')
        # 隐私政策解析线程
        self.policy_analysis_thread = None

        '''隐私政策路径'''
        self.policy_path = ""

        '''布局'''
        self.pa_layout = QVBoxLayout(self)
        self.pa_layout.setAlignment(Qt.AlignTop)
        '''状态栏'''
        self.status_bar = QWidget()
        self.status_bar.setFixedHeight(50)
        self.status_bar_layout = QHBoxLayout(self.status_bar)
        self.status_bar_layout.setAlignment(Qt.AlignLeft)
        # 提示标签
        self.label1 = StrongBodyLabel("当前隐私政策：")
        self.label1.setFixedWidth(120)
        self.label1.setFixedHeight(30)
        # 显示APK名
        self.app_browser = QTextBrowser()
        self.app_browser.setFixedHeight(30)
        self.app_browser.setFixedWidth(400)
        # 将组件添加到布局
        self.status_bar_layout.addWidget(self.label1)
        self.status_bar_layout.addWidget(self.app_browser)
        self.pa_layout.addWidget(self.status_bar)
        '''命令栏'''
        self.commandBar = CommandBar()
        # 图标右侧显示文本
        self.commandBar.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        # 上传 APK 动作
        self.commandBar.addAction(Action(QIcon("./icon/privacy_policy"), '上传隐私政策', triggered=self.open_policy))
        # 添加分隔符
        self.commandBar.addSeparator()
        # 开始检测按钮
        self.commandBar.addAction(Action(QIcon("./icon/start_detect.svg"), '开始分析', triggered=self.analysis_policy))
        self.pa_layout.addWidget(self.commandBar)
        '''结果卡片'''
        self.result_card = ResultCard()
        self.pa_layout.addWidget(self.result_card)

    # 打开隐私政策文件
    def open_policy(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "选择隐私政策文件", "", "Text Files (*.txt)")
        if file_path:
            self.policy_path = file_path
            self.app_browser.setPlainText(file_path.split("/")[-1])

    # 分析隐私政策
    def analysis_policy(self):
        if self.policy_path:
            # 创建进度条
            self.progress_dialog = ProgressDialog(self, "正在解析，请稍等")
            self.progress_dialog.show()
            self.policy_analysis_thread = PolicyAnalysisThread(self.policy_path)
            self.policy_analysis_thread.return_result.connect(self.set_result)
            self.policy_analysis_thread.start()
        else:
            print("请选择隐私政策文件")

    def set_result(self, result):
        for i in range(26):
            if result[f'CR{i+1}']:
                self.result_card.table.setItem(i, 2, QTableWidgetItem('是'))
            else:
                self.result_card.table.setItem(i, 2, QTableWidgetItem('否'))
        self.result_card.table.horizontalHeader().setStretchLastSection(True)
        self.progress_dialog.close()
