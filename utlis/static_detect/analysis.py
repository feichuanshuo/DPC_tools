# APK分析
import json

from androguard.core.apk import APK
from androguard.core.dex import DEX

class ApkAnalysis:
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.apk = APK(apk_path)
        """获取 APK 的基本信息"""
        # 应用名称
        self.app_name = self.apk.get_app_name()
        # APK 的包名
        self.package_name = self.apk.get_package()
        # 应用的版本名
        self.version_name = self.apk.get_androidversion_name()
        # 应用的版本号
        self.version_code = self.apk.get_androidversion_code()
        # 最小 SDK 版本
        self.min_sdk_version = self.apk.get_min_sdk_version()
        # 目标 SDK 版本
        self.target_sdk_version = self.apk.get_target_sdk_version()
        # 权限申请情况
        self.permissions = self.apk.get_permissions()


    # 获取权限使用情况
    def get_permissions_used(self):
        """
        遍历映射关系中的所有危险权限，查找 APK 中是否使用了这些权限相关的敏感API或特定Intent.ACTION/ Content Provider Uri对应字符串
        """
        permission_used = set()

        # 打开权限映射文件
        file_path = "./static/permission_mappings/sdk-" + self.target_sdk_version + ".json"
        with open(file_path, "r") as f:
            permission_mappings = json.load(f)

        # 获取dvm对象
        apk_dex = DEX(self.apk.get_dex())
        # 获取方法中的权限使用情况
        for method in apk_dex.get_methods():
            class_name = method.get_class_name()
            method_name = ""
            if class_name[0] == "[":
                method_name = class_name[2:-1].replace("/", ".") + "." + method.get_name()
            elif class_name[0] == "L":
                method_name = class_name[1:-1].replace("/", ".") + "." + method.get_name()
            # 判断权限使用情况
            for permission in permission_mappings:
                if permission["api_name"] == method_name:
                    permission_used = permission_used | set(permission["permissions"])

        # todo:获取Intent.ACTION/ Content Provider Uri对应字符串中的权限使用情况
        # for string in apk_dex.get_strings():
        #     print(string)
        return permission_used
