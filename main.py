from PySide6 import QtWidgets
from qfluentwidgets import InfoBar, InfoBarPosition
from PySide6.QtGui import Qt
from utlis.init import AdbInit
from components.Dialog.ProgressDialog import ProgressDialog
from components.TabPage.TabPage import TabPage


class MWindow(QtWidgets.QMainWindow):

    _instance = None

    def __init__(self):
        super().__init__()
        self.adb = AdbInit()

        self.resize(1200, 800)
        self.setWindowTitle("APP隐私合规检测")

        self.centralWidget = QtWidgets.QWidget(self)
        self.setCentralWidget(self.centralWidget)

        # central Widget 里面的 主 layout
        self.mainLayout = QtWidgets.QVBoxLayout(self.centralWidget)


        # 展示区
        self.displayTab = TabPage()
        self.mainLayout.addWidget(self.displayTab)
        self.displayTab.ddt_button1.clicked.connect(self.adb.verify)


        # 连接信号与槽
        # 展示消息弹窗的
        self.adb.showInfoBar.connect(self.showInfoBar)
        self.displayTab.showInfoBar.connect(self.showInfoBar)
        # 展示进度条
        self.adb.showProgressDialog.connect(self.showProgressDialog)
        # 关闭进度条
        self.adb.closeProgressDialog.connect(self.closeProgressDialog)

        self.adb.updateAppList.connect(self.displayTab.updateAppList)


    # 消息提示框
    def showInfoBar(self,type,message):
        if type == "success":
            InfoBar.success(
                title='',
                content= message,
                orient=Qt.Horizontal,
                isClosable=True,
                position=InfoBarPosition.TOP,
                duration=2000,
                parent=self
            )
        elif type == "warning":
            InfoBar.warning(
                title='',
                content= message,
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
    app = QtWidgets.QApplication([])
    window = MWindow()
    window.show()
    app.exec()