# 静态检测页面
from PySide6.QtGui import Qt
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QTextBrowser, QFileDialog, QTableWidgetItem
from qfluentwidgets import PushButton, StrongBodyLabel, TitleLabel
from components import MTable, MTree
from utlis.static_detect.analysis import ApkAnalysis

# 权限列表
permission_list = [
    {
        "group": "日历",
        "permissions": [
            {
                "name": "READ_CALENDAR",
                "is_applied": False,
                "is_used": False
            },
            {
                "name": "WRITE_CALENDAR",
                "is_applied": False,
                "is_used": False
            }
        ]
    },
    {
        "group": "相机",
        "permissions": [
            {
                "name": "CAMERA",
                "is_applied": False,
                "is_used": False
            }
        ]
    },
    {
        "group": "联系人",
        "permissions": [
            {
                "name": "READ_CONTACTS",
                "is_applied": False,
                "is_used": False
            },
            {
                "name": "WRITE_CONTACTS",
                "is_applied": False,
                "is_used": False
            },
            {
                "name": "GET_ACCOUNTS",
                "is_applied": False,
                "is_used": False
            }
        ]
    },
    {
        "group": "位置",
        "permissions": [
            {
                "name": "ACCESS_FINE_LOCATION",
                "is_applied": False,
                "is_used": False
            },
            {
                "name": "ACCESS_COARSE_LOCATION",
                "is_applied": False,
                "is_used": False
            }
        ]
    },
    {
        "group": "麦克风",
        "permissions": [
            {
                "name": "RECORD_AUDIO",
                "is_applied": False,
                "is_used": False
            }
        ]
    },
    {
        "group": "电话",
        "permissions": [
            {
                "name": "READ_PHONE_STATE",
                "is_applied": False,
                "is_used": False
            },
            {
                "name": "CALL_PHONE",
                "is_applied": False,
                "is_used": False
            },
            {
                "name": "READ_CALL_LOG",
                "is_applied": False,
                "is_used": False
            },
            {
                "name": "WRITE_CALL_LOG",
                "is_applied": False,
                "is_used": False
            },
            {
                "name": "ADD_VOICEMAIL",
                "is_applied": False,
                "is_used": False
            },
            {
                "name": "USE_SIP",
                "is_applied": False,
                "is_used": False
            },
            {
                "name": "PROCESS_OUTGOING_CALLS",
                "is_applied": False,
                "is_used": False
            },
        ]
    },
    {
        "group": "传感器",
        "permissions": [
            {
                "name": "BODY_SENSORS",
                "is_applied": False,
                "is_used": False
            }
        ]
    },
    {
        "group": "短信",
        "permissions": [
            {
                "name": "SEND_SMS",
                "is_applied": False,
                "is_used": False
            },
            {
                "name": "RECEIVE_SMS",
                "is_applied": False,
                "is_used": False
            },
            {
                "name": "READ_SMS",
                "is_applied": False,
                "is_used": False
            },
            {
                "name": "RECEIVE_WAP_PUSH",
                "is_applied": False,
                "is_used": False
            },
            {
                "name": "RECEIVE_MMS",
                "is_applied": False,
                "is_used": False
            }
        ]
    },
    {
        "group": "存储",
        "permissions": [
            {
                "name": "READ_EXTERNAL_STORAGE",
                "is_applied": False,
                "is_used": False
            },
            {
                "name": "WRITE_EXTERNAL_STORAGE",
                "is_applied": False,
                "is_used": False
            }
        ]
    }
]

class SDPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.sd_layout = QVBoxLayout(self)

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
        self.label1 = StrongBodyLabel("基本信息")
        self.result_layout.addWidget(self.label1)
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
        self.label2 = StrongBodyLabel("权限情况")
        self.result_layout.addWidget(self.label2)
        self.permission_tree = MTree()
        self.result_layout.addWidget(self.permission_tree)

        self.sd_layout.addWidget(self.result_box)

    # 分析APK
    def analysis_apk(self, apk_path=""):
        if apk_path != "":
            # 获取数据
            apk_analysis = ApkAnalysis(apk_path)
            # 设置数据
            self.basic_info_table.setItem(0, 1, QTableWidgetItem(apk_analysis.app_name))
            self.basic_info_table.setItem(0, 3, QTableWidgetItem(apk_analysis.package_name))
            self.basic_info_table.setItem(1, 1, QTableWidgetItem(apk_analysis.version_name))
            self.basic_info_table.setItem(1, 3, QTableWidgetItem(apk_analysis.version_code))
            self.basic_info_table.setItem(2, 1, QTableWidgetItem(apk_analysis.min_sdk_version))
            self.basic_info_table.setItem(2, 3, QTableWidgetItem(apk_analysis.target_sdk_version))
            # 设置应用已经申请的权限
            for item in apk_analysis.permissions:
                for group in permission_list:
                    for permission in group["permissions"]:
                        if item.split(".")[-1] == permission["name"]:
                            permission["is_applied"] = True

            # 设置应用已经使用的权限
            permission_used = apk_analysis.get_permissions_used()
            for item in permission_used:
                for group in permission_list:
                    for permission in group["permissions"]:
                        if item.split(".")[-1] == permission["name"]:
                            permission["is_used"] = True

            self.permission_tree.setData(permission_list)
