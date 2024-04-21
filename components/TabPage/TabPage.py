import base64

from PySide6.QtCore import Signal
from PySide6.QtGui import QImage, QPixmap, Qt
from PySide6.QtWidgets import QTabWidget, QWidget, QVBoxLayout, QTextBrowser, QTableWidgetItem, QHeaderView, \
    QAbstractItemView, QHBoxLayout
from qfluentwidgets import TableWidget, PushButton

from utlis.frida.app import getAppList
from utlis.frida.hook import FridaHook


# 解码base64图片
def decodePicture(imageFile):
    # 解码Base64数据
    image_data = base64.b64decode(imageFile.split(',')[1])

    # 将二进制数据转换为QImage
    image = QImage()
    image.loadFromData(image_data)

    # 将QImage转换为QPixmap
    return QPixmap.fromImage(image)

class TabPage(QTabWidget):
    # 注册信号
    showInfoBar = Signal(str, str)

    def __init__(self):
        super().__init__()
        tab_bar = self.tabBar()
        tab_bar.setStyleSheet("""
            QTabBar::tab {
                font-size: 15px;
            }
        """)

        # 动态检测tab
        self.dynamic_detect_tab = QWidget()
        self.ddt_layout = QVBoxLayout(self.dynamic_detect_tab)
        # 按钮
        self.ddt_button_box = QWidget()
        self.ddt_button_layout = QHBoxLayout(self.ddt_button_box)
        self.ddt_button_layout.setAlignment(Qt.AlignLeft)
        self.ddt_button1 = PushButton("连接设备")
        self.ddt_button1.setFixedWidth(200)
        self.ddt_button2 = PushButton("刷新应用列表")
        self.ddt_button2.setFixedWidth(200)
        self.ddt_button2.clicked.connect(lambda: self.updateAppList(getAppList()))
        self.ddt_button_layout.addWidget(self.ddt_button1)
        self.ddt_button_layout.addWidget(self.ddt_button2)
        self.ddt_layout.addWidget(self.ddt_button_box)
        # app列表
        self.app_list_box = QWidget()
        self.app_list_layout = QVBoxLayout(self.app_list_box)
        self.app_list = TableWidget()
        # 启用边框并设置圆角
        self.app_list.setBorderVisible(True)
        self.app_list.setBorderRadius(8)
        # 设置表格行列数及不自动换行
        self.app_list.setWordWrap(False)
        self.app_list.setRowCount(0)
        self.app_list.setColumnCount(4)
        # 设置水平表头并隐藏垂直表头
        self.app_list.setHorizontalHeaderLabels(['应用名称', '包名', '应用版本', '操作'])
        self.app_list.verticalHeader().hide()
        # 设置行高
        self.app_list.verticalHeader().setDefaultSectionSize(50)
        # 设置列宽
        self.app_list.setColumnWidth(0, 300)
        self.app_list.setColumnWidth(1, 300)
        self.app_list.setColumnWidth(2,200)
        self.app_list.horizontalHeader().setStretchLastSection(True)
        # 设置表格不可拖动
        self.app_list.horizontalHeader().setSectionResizeMode(QHeaderView.Fixed)
        # 设置表格不可编辑
        self.app_list.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # 设置表格不可选中
        self.app_list.setSelectionMode(QAbstractItemView.NoSelection)
        self.app_list_layout.addWidget(self.app_list)
        self.ddt_layout.addWidget(self.app_list_box)
        self.addTab(self.dynamic_detect_tab,"动态检测")


        # 静态检测tab
        self.static_detect_tab = QWidget()
        self.static_detect_layout = QVBoxLayout(self.static_detect_tab)
        self.sd_browser = QTextBrowser()
        self.sd_browser.setPlainText("静态检测结果")
        self.static_detect_layout.addWidget(self.sd_browser)
        self.addTab(self.static_detect_tab, "静态检测")


        # 合规性分析tab
        self.complianceAnalysisTab = QWidget()
        self.complianceAnalysisLayout = QVBoxLayout(self.complianceAnalysisTab)
        self.cABrowser = QTextBrowser()
        self.cABrowser.setPlainText("合规性分析结果")
        self.complianceAnalysisLayout.addWidget(self.cABrowser)
        self.addTab(self.complianceAnalysisTab, "合规性分析")

    # 更新app列表
    def updateAppList(self, data, is_init=False):
        def hook(app_name):
            fh = FridaHook(app_name)
            fh.start()


        if data != []:
            self.app_list.setRowCount(len(data))
            i = 0
            for item in data:
                # 设置app图标
                iconPixmap = decodePicture(item["icon"])
                nameItem = QTableWidgetItem(item["name"])
                nameItem.setIcon(iconPixmap)
                # 添加按钮
                button = PushButton("开始检测")
                button.setFixedHeight(30)
                button.setFixedWidth(200)
                button.clicked.connect(lambda checked, package=item["package"]: hook(package))
                # 创建一个水平布局管理器
                button_layout = QHBoxLayout()
                button_widget = QWidget()
                button_layout.addWidget(button)
                button_layout.setAlignment(Qt.AlignCenter)  # 水平居中按钮

                # 将布局管理器设置为按钮小部件的布局
                button_widget.setLayout(button_layout)
                self.app_list.setItem(i,0, nameItem)
                self.app_list.setItem(i, 1, QTableWidgetItem(item["package"]))
                self.app_list.setItem(i, 2, QTableWidgetItem(item["version"]))
                self.app_list.setCellWidget(i, 3, button_widget)
                i = i+1

            self.showInfoBar.emit("success", "获取应用列表成功")
