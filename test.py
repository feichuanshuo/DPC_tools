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

from utils.common.nlp_utils import seg_by_jieba


def extract_pi(text):
    # english_PI_model = ['email', 'e-mail', 'iccid', 'sim', 'imei', 'imsi', 'androidid', 'adid', 'android sn',
    #                     'idfa', 'openudid', 'guid', 'wi-fi', 'wifi', 'wlan', 'nfc', 'dna']
    # for keyword in english_PI_model:
    #     if keyword in text.lower():
    #         print(keyword)
    print(seg_by_jieba(text, remove_stopwords=True))


if __name__ == '__main__':
    # extract_app_name("E:/Project/example/privacy_policy/001.同花顺.txt")
    extract_pi("同时，我们会根据监管机构要求收集您的个人身份信息，以及办理网上开户业务法律法规所规定的信息， 包括您的姓名、性别、民族、国籍、出生日期、证件类型、证件号码、证件签发机关、证件有效期、有效身份证件的彩色照片、个人生物识别信息、开户声明视频、联系电话、联系地址（常住地址）、职业、学历、银行卡号信息、税收居民身份、财务状况、收入来源、诚信信息、债务情况、投资相关的学习、工作经历和投资风险信息、风险偏好及可承受的损失、投资期限、品种、期望收益投资目标信息、实际控制投资者的自然人和交易的实际受益人、法律法规、行业自律规则规定的投资者准入要求的相关信息")