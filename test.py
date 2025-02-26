import uiautomator2 as u2
#
#
# device = u2.connect()
# print(device.app_current())
# package_name = device.app_current()['package']
# print(package_name)

# import subprocess
#
#
# def get_pid(package_name):
#     # 构建adb命令
#     cmd = f"adb shell ps | grep {package_name} | head -n 1 | awk '{{print $2}}'"
#
#     # 执行命令并获取输出
#     result = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()
#
#     outdata = result[0].decode("utf-8")
#
#     return outdata if outdata else 0
#
# print(get_pid(package_name))
# import subprocess
#
# from configuration import adb_path
#
# result=subprocess.run(f"adb connect 127.0.0.1:7555", shell=True, check=True)
# res = subprocess.run("adb devices", shell=True, capture_output=True, text=True)
#
# print(result)
# print(res)

# device = u2.connect()
#
# xml = device.dump_hierarchy()
# with open("error_screenshot_dir.xml", "w", encoding='utf-8') as f:
#     f.write(xml)
# def extract_app_name(policy_path):
#     """
#     从隐私政策路径中提取 APP 名称
#     :param policy_path: 隐私政策路径
#     :return: APP 名称
#     """
#     # 获取文件名（去掉路径）
#     file_name = policy_path.split('/')[-1]  # Windows 路径分隔符
#
#     # 提取 APP 名称
#     app_name = file_name[:-4]
#
#     print(app_name)
#     return app_name


def extract_pi(text):
    english_PI_model = ['email', 'e-mail', 'iccid', 'sim', 'imei', 'imsi', 'androidid', 'adid', 'android sn',
                        'idfa', 'openudid', 'guid', 'wi-fi', 'wifi', 'wlan', 'nfc', 'dna']
    for keyword in english_PI_model:
        if keyword in text.lower():
            print(keyword)

if __name__ == '__main__':
    # extract_app_name("E:/Project/example/privacy_policy/001.同花顺.txt")
    extract_pi("当你使用“Faceu激萌”及相关服务时，为了保障软件与服务的正常运行，我们会收集你的硬件型号、操作系统版本号、国际移动设备识别码（IMEI）、网络设备硬件地址（MAC）、IP地址、软件版本号、网络接入方式及类型、操作日志等信息")