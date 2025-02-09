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

device = u2.connect()

xml = device.dump_hierarchy()
with open("error_screenshot_dir.xml", "w", encoding='utf-8') as f:
    f.write(xml)

