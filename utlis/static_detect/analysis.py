# APK分析
from androguard.core.apk import APK
from androguard.core.analysis import analysis

class ApkAnalysis:
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.apk = APK(apk_path)
        # self.analysis = analysis.Analysis(self.apk)

    # 获取应用名称
    def get_app_name(self):
        return self.apk.get_app_name()

    # 获取 APK 的包名
    def get_package(self):
        return self.apk.get_package()

    # 获取应用的版本名
    def get_version_name(self):
        return self.apk.get_androidversion_name()

    # 获取应用的版本号
    def get_version_code(self):
        return self.apk.get_androidversion_code()

    # 获取最小 SDK 版本
    def get_min_sdk_version(self):
        return self.apk.get_min_sdk_version()
    # 获取目标 SDK 版本
    def get_target_sdk_version(self):
        return self.apk.get_target_sdk_version()

    # 获取 ARK 申请的权限列表
    def get_permissions(self):
        return self.apk.get_permissions()

    # 获取 APK 所用的 activity
    def get_activities(self):
        return self.apk.get_activities()

    # 获取 APK 的 AndroidManifest.xml 文件的 ElementTree 对象
    def get_android_manifest_xml(self):
        return self.apk.get_android_manifest_xml()

    # def get_analysis(self):
    #     return self.analysis