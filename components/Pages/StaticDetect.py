# 静态检测页面
from PySide6.QtWidgets import QWidget, QVBoxLayout, QTextBrowser


class SDPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.sd_layout = QVBoxLayout(self)
        self.sd_browser = QTextBrowser()
        self.sd_browser.setPlainText("静态分析结果")
        self.sd_layout.addWidget(self.sd_browser)