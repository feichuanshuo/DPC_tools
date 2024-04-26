# 动态检测页面
import base64

from PySide6.QtCore import Signal
from PySide6.QtGui import Qt, QImage, QPixmap
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QTableWidgetItem
from qfluentwidgets import PushButton

from components import MTable
from components.Dialog.DynamicDetectDialog import DynamicDetectDialog
from utlis.dynamic_detect.app import getAppList
from utlis.dynamic_detect.init import AdbInit


# 解码base64图片
def decodePicture(imageFile):
    # 解码Base64数据
    image_data = base64.b64decode(imageFile.split(',')[1])

    # 将二进制数据转换为QImage
    image = QImage()
    image.loadFromData(image_data)

    # 将QImage转换为QPixmap
    return QPixmap.fromImage(image)

class DDPage(QWidget):
    # 注册信号
    showInfoBar = Signal(str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.adb = AdbInit()

        self.dd_layout = QVBoxLayout(self)

        # 按钮
        self.dd_button_box = QWidget()
        self.dd_button_layout = QHBoxLayout(self.dd_button_box)
        self.dd_button_layout.setAlignment(Qt.AlignLeft)
        self.dd_button1 = PushButton("连接设备")
        self.dd_button1.setFixedWidth(200)
        self.dd_button1.clicked.connect(self.adb.verify)
        self.dd_button2 = PushButton("刷新应用列表")
        self.dd_button2.setFixedWidth(200)
        self.dd_button2.clicked.connect(lambda: self.updateAppList(getAppList()))
        self.dd_button_layout.addWidget(self.dd_button1)
        self.dd_button_layout.addWidget(self.dd_button2)
        self.dd_layout.addWidget(self.dd_button_box)

        # app列表
        self.app_list_box = QWidget()
        self.app_list_layout = QVBoxLayout(self.app_list_box)
        self.app_list = MTable()
        # 设置表格行列数
        self.app_list.setRowCount(0)
        self.app_list.setColumnCount(4)
        # 设置水平表头
        self.app_list.setHorizontalHeaderLabels(['应用名称', '包名', '应用版本', '操作'])
        # 设置列宽
        self.app_list.setColumnWidth(0, 300)
        self.app_list.setColumnWidth(1, 300)
        self.app_list.setColumnWidth(2, 200)
        self.app_list.horizontalHeader().setStretchLastSection(True)

        # 设置行高
        self.app_list.verticalHeader().setDefaultSectionSize(50)
        self.app_list_layout.addWidget(self.app_list)
        self.dd_layout.addWidget(self.app_list_box)

        self.adb.updateAppList.connect(self.updateAppList)

    # 动态检测弹窗
    def showDDDialog(self, app_info):
        main_window = self.parent().parent().parent()
        dd_dialog = DynamicDetectDialog(main_window, app_info)
        dd_dialog.show()

    # 更新app列表
    def updateAppList(self, data, is_init=False):
        if data != []:
            self.app_list.setRowCount(len(data))
            for row, item in enumerate(data):
                # 设置app图标
                iconPixmap = decodePicture(item["icon"])
                nameItem = QTableWidgetItem(item["name"])
                nameItem.setIcon(iconPixmap)
                # 添加按钮
                button = PushButton("开始检测")
                button.setFixedHeight(30)
                button.setFixedWidth(200)
                button.clicked.connect(lambda checked, app_info=item: self.showDDDialog(app_info))
                # 创建一个水平布局管理器
                button_layout = QHBoxLayout()
                button_widget = QWidget()
                button_layout.addWidget(button)
                button_layout.setAlignment(Qt.AlignCenter)  # 水平居中按钮

                # 将布局管理器设置为按钮小部件的布局
                button_widget.setLayout(button_layout)
                self.app_list.setItem(row, 0, nameItem)
                self.app_list.setItem(row, 1, QTableWidgetItem(item["package"]))
                self.app_list.setItem(row, 2, QTableWidgetItem(item["version"]))
                self.app_list.setCellWidget(row, 3, button_widget)

            self.showInfoBar.emit("success", "获取应用列表成功")