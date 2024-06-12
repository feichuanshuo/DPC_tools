from PySide6.QtWidgets import QStackedWidget, QMainWindow, QWidget, QVBoxLayout, QApplication
from qfluentwidgets import InfoBar, InfoBarPosition, SegmentedWidget
from PySide6.QtGui import Qt
from components.FunctionArea import FunctionArea
from components import ProgressDialog
from components.Pages.StaticDetect import SDPage
# 新
from components.Pages.DynamicDetect import DDPage
# 旧
# from components.Pages.DeviceInfor import DDPage
from components.Pages.ComplianceAnalysis import CAPage


class MWindow(QMainWindow):

    def __init__(self):
        super().__init__()

        self.resize(1200, 800)
        self.setWindowTitle("APP隐私合规检测")

        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)

        # central Widget 里面的 主 layout
        self.main_layout = QVBoxLayout(self.central_widget)

        # 功能区域
        self.function_area = FunctionArea(self)
        self.main_layout.addWidget(self.function_area)

        # 结果展示区
        self.result_area = QWidget(self)
        self.result_area.setObjectName("mw-resultArea")
        self.result_area.setStyleSheet(
            "#mw-resultArea {background-color: white; border-radius: 8px;}"
        )
        self.result_area_layout = QVBoxLayout(self.result_area)
        self.navigation = SegmentedWidget(self)
        self.stacked_widget = QStackedWidget(self)
        self.stacked_widget.setObjectName("mw-stackedWidget")
        self.stacked_widget.setStyleSheet(
            "#mw-stackedWidget {background-color: white; border-radius: 8px; }"
        )

        # 静态检测页
        self.static_detect_page = SDPage(self)
        # 动态检测页
        self.dynamic_detect_page = DDPage(self)
        # 合规分析页
        self.compliance_analysis_page = CAPage(self)

        # 添加标签页
        self.addSubInterface(self.static_detect_page, "static_detect_page", "静态检测")
        self.addSubInterface(self.dynamic_detect_page, "dynamic_detect_page", "动态检测")
        self.addSubInterface(self.compliance_analysis_page, "compliance_analysis_page", "合规分析")

        # 连接信号并初始化当前标签页
        self.stacked_widget.currentChanged.connect(self.onCurrentIndexChanged)
        self.stacked_widget.setCurrentWidget(self.static_detect_page)
        self.navigation.setCurrentItem(self.static_detect_page.objectName())

        self.result_area_layout.addWidget(self.navigation, 0, Qt.AlignLeft)
        self.result_area_layout.addWidget(self.stacked_widget)
        self.main_layout.addWidget(self.result_area)

        """连接信号与槽"""
        # 静态检测
        self.function_area.startStaticDetect.connect(self.static_detect_page.analysis_apk)
        # 动态检测
        self.function_area.startDynamicDetect.connect(self.dynamic_detect_page.start_detect)
        # 展示消息弹窗的
        self.function_area.adb.showInfoBar.connect(self.showInfoBar)
        self.function_area.showInforBar.connect(self.showInfoBar)
        self.dynamic_detect_page.fh.showInfoBar.connect(self.showInfoBar)
        # 展示进度条
        self.function_area.adb.showProgressDialog.connect(self.showProgressDialog)
        # 关闭进度条
        self.function_area.adb.closeProgressDialog.connect(self.closeProgressDialog)
        # 设置设备状态
        self.function_area.adb.setDeviceStatus.connect(self.function_area.set_device_status)

    # 添加标签页
    def addSubInterface(self, widget: QWidget, object_name: str, text: str):
        widget.setObjectName(object_name)
        self.stacked_widget.addWidget(widget)

        # 使用全局唯一的 objectName 作为路由键
        self.navigation.addItem(
            routeKey=object_name,
            text=text,
            onClick=lambda: self.stacked_widget.setCurrentWidget(widget)
        )

    def onCurrentIndexChanged(self, index):
        widget = self.stacked_widget.widget(index)
        self.navigation.setCurrentItem(widget.objectName())

    # 消息提示框
    def showInfoBar(self, message_type, message):
        if message_type == "success":
            InfoBar.success(
                title='',
                content=message,
                orient=Qt.Horizontal,
                isClosable=True,
                position=InfoBarPosition.TOP,
                duration=2000,
                parent=self
            )
        elif message_type == "warning":
            InfoBar.warning(
                title='',
                content=message,
                orient=Qt.Horizontal,
                isClosable=True,
                position=InfoBarPosition.TOP,
                duration=2000,
                parent=self
            )
        elif message_type == "error":
            InfoBar.error(
                title='',
                content=message,
                orient=Qt.Horizontal,
                isClosable=True,
                position=InfoBarPosition.TOP,
                duration=2000,
                parent=self
            )

    # 显示进度条
    def showProgressDialog(
            self,
            title,
            hide_yes_button=True,
            hide_cancel_button=True,
            yes_button_text="确定",
            cancel_button_text="取消",
    ):
        self.pd = ProgressDialog(
            self,
            title,
            hide_yes_button,
            hide_cancel_button,
            yes_button_text,
            cancel_button_text
        )
        self.pd.show()

    # 关闭进度条
    def closeProgressDialog(self):
        self.pd.close()
        del self.pd


if __name__ == '__main__':
    app = QApplication([])
    window = MWindow()
    window.show()
    app.exec()
