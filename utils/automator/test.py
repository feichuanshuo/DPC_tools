import uiautomator2 as u2


device = u2.connect()
print(device.app_current())
package_name = device.app_current()['package']
print(package_name)

import subprocess


def get_pid(package_name):
    # 构建adb命令
    cmd = f"adb shell ps | grep {package_name} | head -n 1 | awk '{{print $2}}'"

    # 执行命令并获取输出
    result = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()

    outdata = result[0].decode("utf-8")

    return outdata if outdata else 0

print(get_pid(package_name))

