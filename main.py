from PySide6.QtWidgets import QStackedWidget, QMainWindow, QWidget, QVBoxLayout, QApplication
from qfluentwidgets import InfoBar, InfoBarPosition, SegmentedWidget
from PySide6.QtGui import Qt
from components import ProgressDialog
from components.Pages.StaticDetect import SDPage
from components.Pages.DynamicDetect import DDPage
from components.Pages.ComplianceAnalysis import CAPage


class MWindow(QMainWindow):

    def __init__(self):
        super().__init__()

        self.resize(1200, 800)
        self.setWindowTitle("APP隐私合规检测")

        self.centralWidget = QWidget(self)
        self.setCentralWidget(self.centralWidget)

        # central Widget 里面的 主 layout
        self.mainLayout = QVBoxLayout(self.centralWidget)
        self.navigation = SegmentedWidget(self)
        self.stackedWidget = QStackedWidget(self)
        self.stackedWidget.setObjectName("mw-stackedWidget")
        self.stackedWidget.setStyleSheet("#mw-stackedWidget {background-color: white; border-radius: 8px;margin: 0px 10px 10px; }")

        # 静态检测页
        self.static_detect_page = SDPage()
        # 动态检测页
        self.dynamic_detect_page = DDPage()
        # 合规分析页
        self.compliance_analysis_page = CAPage()

        # 添加标签页
        self.addSubInterface(self.static_detect_page, "static_detect_page", "静态检测")
        self.addSubInterface(self.dynamic_detect_page, "dynamic_detect_page", "动态检测")
        self.addSubInterface(self.compliance_analysis_page, "compliance_analysis_page", "合规分析")

        # 连接信号并初始化当前标签页
        self.stackedWidget.currentChanged.connect(self.onCurrentIndexChanged)
        self.stackedWidget.setCurrentWidget(self.static_detect_page)
        self.navigation.setCurrentItem(self.static_detect_page.objectName())

        self.mainLayout.addWidget(self.navigation, 0, Qt.AlignHCenter)
        self.mainLayout.addWidget(self.stackedWidget)



        # 连接信号与槽
        # 展示消息弹窗的
        self.dynamic_detect_page.adb.showInfoBar.connect(self.showInfoBar)
        self.dynamic_detect_page.showInfoBar.connect(self.showInfoBar)
        # 展示进度条
        self.dynamic_detect_page.adb.showProgressDialog.connect(self.showProgressDialog)
        # 关闭进度条
        self.dynamic_detect_page.adb.closeProgressDialog.connect(self.closeProgressDialog)

    # 添加标签页
    def addSubInterface(self, widget: QWidget, object_name: str, text: str):
        widget.setObjectName(object_name)
        self.stackedWidget.addWidget(widget)

        # 使用全局唯一的 objectName 作为路由键
        self.navigation.addItem(
            routeKey=object_name,
            text=text,
            onClick=lambda: self.stackedWidget.setCurrentWidget(widget)
        )

    def onCurrentIndexChanged(self, index):
        widget = self.stackedWidget.widget(index)
        self.navigation.setCurrentItem(widget.objectName())

    # 消息提示框
    def showInfoBar(self, type, message):
        if type == "success":
            InfoBar.success(
                title='',
                content=message,
                orient=Qt.Horizontal,
                isClosable=True,
                position=InfoBarPosition.TOP,
                duration=2000,
                parent=self
            )
        elif type == "warning":
            InfoBar.warning(
                title='',
                content=message,
                orient=Qt.Horizontal,
                isClosable=True,
                position=InfoBarPosition.TOP,
                duration=2000,
                parent=self
            )
        elif type == "error":
            InfoBar.error(
                title='',
                content= message,
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