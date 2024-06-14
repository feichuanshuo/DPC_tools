from PySide6.QtCore import Signal
from PySide6.QtGui import Qt, QIcon
from PySide6.QtWidgets import QWidget, QHBoxLayout, QTextBrowser, QFileDialog, QVBoxLayout
from qfluentwidgets import StrongBodyLabel, CommandBar, Action

from utils.dynamic_detect.init import AdbInit
from utils.dynamic_detect.hook import FridaHook


class FunctionArea(QWidget):
    # 注册信号
    startStaticDetect = Signal(str)
    startDynamicDetect = Signal(str)
    showInforBar = Signal(str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        """apk路径"""
        self.apk_path = ""

        self.adb = AdbInit()

        self.commandBar = CommandBar()
        # 图标右侧显示文本
        self.commandBar.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)

        # 上传 APK 动作
        self.commandBar.addAction(Action(QIcon("./icon/apk.svg"), '上传APK', triggered=self.open_apk))
        # 添加分隔符
        self.commandBar.addSeparator()
        # 连接设备动作
        self.commandBar.addAction(Action(QIcon("./icon/USB.svg"), '连接设备', triggered=self.connect_device))
        # 添加分隔符
        self.commandBar.addSeparator()

        # 批量添加动作
        self.commandBar.addActions([
            Action(QIcon("./icon/static_detect.svg"), '开始静态检测', triggered=self.start_static_detect),
            Action(QIcon("./icon/dynamic_detect.svg"), '开始动态检测', triggered=self.start_dynamic_detect)
        ])

        # 总布局
        self.setFixedHeight(100)
        self.function_area_layout = QVBoxLayout(self)

        # 设置状态栏布局
        self.status_bar = QWidget()
        self.status_bar.setFixedHeight(50)
        self.function_area_layout.addWidget(self.status_bar)
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
        # 间隔符
        spacer = QWidget()
        spacer.setFixedSize(20, 1)  # 设置间隔的宽度和高度
        # 提示标签
        self.label2 = StrongBodyLabel("设备状态：")
        self.label2.setFixedWidth(80)
        self.label2.setFixedHeight(30)
        # 显示设备状态
        self.device_status = QTextBrowser()
        self.device_status.setFixedHeight(30)
        self.device_status.setFixedWidth(100)
        self.device_status.setText("未连接")

        # 将组件添加到布局
        self.status_bar_layout.addWidget(self.label1)
        self.status_bar_layout.addWidget(self.app_browser)
        self.status_bar_layout.addWidget(spacer)
        self.status_bar_layout.addWidget(self.label2)
        self.status_bar_layout.addWidget(self.device_status)
        self.function_area_layout.addWidget(self.commandBar)

    # 打开APK文件
    def open_apk(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "选择APK文件", "", "APK Files (*.apk)")
        if file_path:
            self.apk_path = file_path
            self.app_browser.setPlainText(file_path.split("/")[-1])

    # 连接设备
    def connect_device(self):
        self.adb.verify()

    # 设置设备状态
    def set_device_status(self, status):
        self.device_status.setText(status)

    # 开始静态检测
    def start_static_detect(self):
        if self.apk_path == "":
            self.showInforBar.emit("warning", "请先上传APK文件")
            return
        self.startStaticDetect.emit(self.apk_path)

    # 开始动态检测
    def start_dynamic_detect(self):
        if self.apk_path == "":
            self.showInforBar.emit("warning", "请先上传APK文件")
            return
        self.startDynamicDetect.emit(self.apk_path)
