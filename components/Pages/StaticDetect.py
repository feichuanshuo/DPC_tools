# 静态检测页面
from PySide6.QtGui import Qt
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QTextBrowser, QFileDialog, QTableWidgetItem
from qfluentwidgets import PushButton, StrongBodyLabel, TitleLabel
from components import MTable
from utlis.static_detect.analysis import ApkAnalysis


class SDPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        """apk路径"""
        self.apk_path = ""

        self.sd_layout = QVBoxLayout(self)

        """选择APK"""
        # 设置布局
        self.apk_input_box = QWidget()
        self.apk_input_box.setFixedHeight(50)
        self.apk_input_layout = QHBoxLayout(self.apk_input_box)
        self.apk_input_layout.setAlignment(Qt.AlignCenter)
        # 提示标签
        self.label1 = StrongBodyLabel("当前APK：")
        self.label1.setFixedWidth(80)
        self.label1.setFixedHeight(30)
        # 显示APK名
        self.app_browser = QTextBrowser()
        self.app_browser.setFixedHeight(30)
        self.app_browser.setFixedWidth(400)
        # 选择文件按钮
        self.open_apk_btn = PushButton("选择文件")
        self.open_apk_btn.setFixedWidth(80)
        self.open_apk_btn.setFixedHeight(30)
        self.open_apk_btn.clicked.connect(self.open_apk)
        # 开始检测按钮
        self.start_detect_btn = PushButton("开始检测")
        self.start_detect_btn.setFixedWidth(80)
        self.start_detect_btn.setFixedHeight(30)
        self.start_detect_btn.clicked.connect(self.analysis_apk)
        # 将组件添加到布局
        self.apk_input_layout.addWidget(self.label1)
        self.apk_input_layout.addWidget(self.app_browser)
        self.apk_input_layout.addWidget(self.open_apk_btn)
        self.apk_input_layout.addWidget(self.start_detect_btn)
        self.sd_layout.addWidget(self.apk_input_box)

        """检测结果"""
        self.result_box = QWidget()
        self.result_box.setObjectName("sd-result-box")
        self.result_box.setStyleSheet("#sd-result-box {border-radius: 5px; border: 1px solid #ccc;}")
        self.result_layout = QVBoxLayout(self.result_box)
        # 设置标题
        self.result_box_title = QWidget()
        self.result_box_title_layout = QHBoxLayout(self.result_box_title)
        self.result_box_title_layout.setAlignment(Qt.AlignCenter)
        self.result_box_title_label = TitleLabel("检测结果")
        self.result_box_title_layout.addWidget(self.result_box_title_label)
        self.result_layout.addWidget(self.result_box_title)

        # 基本信息
        self.label2 = StrongBodyLabel("基本信息")
        self.result_layout.addWidget(self.label2)
        self.basic_info_table = MTable()
        self.basic_info_table.setFixedHeight(155)
        # 设置行数和列数
        self.basic_info_table.setColumnCount(4)
        self.basic_info_table.setRowCount(3)
        # 隐藏表头
        self.basic_info_table.horizontalHeader().hide()
        # 设置列宽
        self.basic_info_table.setColumnWidth(0, 150)
        self.basic_info_table.setColumnWidth(1, 350)
        self.basic_info_table.setColumnWidth(2, 150)
        self.basic_info_table.horizontalHeader().setStretchLastSection(True)
        # 设置行高
        self.basic_info_table.verticalHeader().setDefaultSectionSize(50)
        # 设置表格内容
        self.basic_info_table.setItem(0, 0, QTableWidgetItem("应用名称"))
        self.basic_info_table.setItem(0, 2, QTableWidgetItem("应用包名"))
        self.basic_info_table.setItem(1, 0, QTableWidgetItem("应用版本名称"))
        self.basic_info_table.setItem(1, 2, QTableWidgetItem("应用版本号"))
        self.basic_info_table.setItem(2, 0, QTableWidgetItem("最小SDK版本"))
        self.basic_info_table.setItem(2, 2, QTableWidgetItem("目标SDK版本"))
        self.result_layout.addWidget(self.basic_info_table)

        # 权限情况
        self.label3 = StrongBodyLabel("权限情况")
        self.result_layout.addWidget(self.label3)

        self.result_browser = QTextBrowser()
        self.result_browser.setPlainText("检测结果")
        self.result_layout.addWidget(self.result_browser)
        self.sd_layout.addWidget(self.result_box)

    # 打开APK文件
    def open_apk(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "选择APK文件", "", "APK Files (*.apk)")
        if file_path:
            self.apk_path = file_path
            self.app_browser.setPlainText(file_path.split("/")[-1])

    # 分析APK
    def analysis_apk(self):
        if self.apk_path != "":
            # 获取数据
            apk_analysis = ApkAnalysis(self.apk_path)
            app_name = apk_analysis.get_app_name()
            package_name = apk_analysis.get_package()
            version_name = apk_analysis.get_version_name()
            version_code = apk_analysis.get_version_code()
            min_sdk_version = apk_analysis.get_min_sdk_version()
            target_sdk_version = apk_analysis.get_target_sdk_version()
            # 设置数据
            self.basic_info_table.setItem(0, 1, QTableWidgetItem(app_name))
            self.basic_info_table.setItem(0, 3, QTableWidgetItem(package_name))
            self.basic_info_table.setItem(1, 1, QTableWidgetItem(version_name))
            self.basic_info_table.setItem(1, 3, QTableWidgetItem(version_code))
            self.basic_info_table.setItem(2, 1, QTableWidgetItem(min_sdk_version))
            self.basic_info_table.setItem(2, 3, QTableWidgetItem(target_sdk_version))

            print(apk_analysis.get_android_manifest_xml())
