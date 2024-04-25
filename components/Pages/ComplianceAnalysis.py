# 合规性检测页面
from PySide6.QtWidgets import QWidget, QVBoxLayout, QTextBrowser


class CAPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.ca_layout = QVBoxLayout(self)
        self.ca_browser = QTextBrowser()
        self.ca_browser.setPlainText("合规性分析结果")
        self.ca_layout.addWidget(self.ca_browser)