# 连接设备
import os
import time
import subprocess
from threading import Thread

from PySide6.QtCore import QObject, Signal

from utlis.app import getAppList

# 定义不同手机架构的frida-server名称
frida_server_arm = "hluda-server-arm64"
frida_server_x86 = "hluda-server-x86"

class AdbInit(QObject):

    # 注册信号
    showInfoBar = Signal(str,str)
    showProgressDialog = Signal(str)
    closeProgressDialog = Signal()
    updateAppList = Signal(list, bool)

    def __init__(self):
        super().__init__()
        self.adb_path = (
            os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
            + os.sep
            + "static"
            + os.sep
            + "windows"
            + os.sep
            + "adb.exe"
        )
        self.frida_server = ""
        self.frida_path = (
            os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
            + os.sep
            + "static"
            + os.sep
            + self.frida_server
        )
        # 列出连接到计算机的所有设备。
        self.devices_cmd = [self.adb_path, "devices"]
        # 检查设备是否已经root
        self.root_cmd = [self.adb_path, "shell", "su -c 'exit'"]
        # 获取连接的Android设备的CPU架构
        self.detecting_phone_architecture_cmd = [self.adb_path, "shell", "su -c 'getprop ro.product.cpu.abi'"]
        # 停止adb服务器
        self.stop_adb_cmd = [self.adb_path, "kill-server"]
        # 启动adb服务器
        self.start_adb_cmd = [self.adb_path, "start-server"]
        # 在设备上禁用SELinux，这通常是进行调试和其他高级操作所必需的。
        self.colse_SELinux_cmd = [self.adb_path, "shell", "su -c 'setenforce 0'"]
        # https://github.com/frida/frida/issues/1788
        # 禁用USAP池
        self.close_usap_cmd = [
            self.adb_path,
            "shell",
            "su -c 'setprop persist.device_config.runtime_native.usap_pool_enabled false'",
        ]

        # 在设备上杀死任何正在运行的Frida服务器实例
        self.kill_cmd = [self.adb_path, "shell", "su -c 'pkill -9 hluda'"]
        # 删除设备上/data/local/tmp目录中的所有文件。
        self.clean_cmd = [self.adb_path, "shell", "su -c 'rm -rf /data/local/tmp/*'"]
        # 检测手机架构
        self.detecting_phone_architecture_cmd = [
            self.adb_path,
            "shell",
            "su -c 'getprop ro.product.cpu.abi'",
        ]
        # 在设备上禁用SELinux，这通常是进行调试和其他高级操作所必需的。
        self.colse_SELinux_cmd = [self.adb_path, "shell", "su -c 'setenforce 0'"]
        # 在设备上杀死任何正在运行的Frida服务器实例
        self.kill_cmd = [self.adb_path, "shell", "su -c 'pkill -9 hluda'"]
        # 删除设备上/data/local/tmp目录中的所有文件。
        self.clean_cmd = [self.adb_path, "shell", "su -c 'rm -rf /data/local/tmp/*'"]
        # 将Frida服务器二进制文件推送到设备上的/storage/emulated/0目录。
        self.push_cmd = [self.adb_path, "push", self.frida_path, "/storage/emulated/0/{}".format(self.frida_server)]
        # 将Frida服务器二进制文件移动到设备上的/data/local/tmp目录。
        self.mv_cmd = [
            self.adb_path,
            "shell",
            "su -c 'mv /storage/emulated/0/{} /data/local/tmp/'".format(self.frida_server),
        ]
        # 更改Frida服务器二进制文件的权限。
        self.chmod_cmd = [
            self.adb_path,
            "shell",
            "su -c 'chmod 777 /data/local/tmp/{}'".format(self.frida_server),
        ]
        # 在设备上启动Frida服务器。
        self.run_cmd = [self.adb_path, "shell", "su -c 'nohup /data/local/tmp/{} &'".format(self.frida_server)]


    # 获取手机的架构
    def detecting_phone_architecture(self):
        # 检测手机架构
        result = subprocess.Popen(self.detecting_phone_architecture_cmd, stdout=subprocess.PIPE).communicate()
        outdata = result[0].decode("utf-8")
        if "arm" in outdata:
            self.frida_server = frida_server_arm
        elif "x86" in outdata:
            self.frida_server = frida_server_x86
        else:
            raise Exception("手机架构不支持", outdata)

    # 更新命令行指令
    def update_cmd(self):
        self.frida_path = (
            os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
            + os.sep
            + "static"
            + os.sep
            + self.frida_server
        )
        self.push_cmd = [self.adb_path, "push", self.frida_path, "/storage/emulated/0/{}".format(self.frida_server)]
        self.mv_cmd = [
            self.adb_path,
            "shell",
            "su -c 'mv /storage/emulated/0/{} /data/local/tmp/'".format(self.frida_server),
        ]
        self.chmod_cmd = [
            self.adb_path,
            "shell",
            "su -c 'chmod 777 /data/local/tmp/{}'".format(self.frida_server),
        ]
        self.run_cmd = [self.adb_path, "shell", "su -c 'nohup /data/local/tmp/{} &'".format(self.frida_server)]

    # 检查设备是否连接及是否已经root等
    def verify(self):
        try:
            # 确认是否打开了 usb 调试
            result = subprocess.Popen(self.devices_cmd, stdout=subprocess.PIPE).communicate()
            if (
                    result[0].decode("utf-8").split("\n")[1] == ""
                    or result[0].decode("utf-8").split("\n")[1] == "\r"
            ):  # 兼容win
                # 未打开 USB 调试
                # 设备未连接
                self.showInfoBar.emit("warning", "设备未连接或未开启 USB 调试")
                return
            if result[0].decode("utf-8").split("\n")[1].split()[1] == "unauthorized":
                # 未打开 USB 调试
                # 设备未连接
                self.showInfoBar.emit("warning", "未授权 USB 调试")
                return
            if result[0].decode("utf-8").split("\n")[1].split()[1] == "device":
                root_check = subprocess.call(self.root_cmd)
                if root_check != 0:
                    self.showInfoBar.emit("warning", "未开启或未授权 ROOT")
                    return
                self.showInfoBar.emit("success", "设备连接成功")
                # 在新线程中执行耗时的初始化操作
                self.init_thread = Thread(target=self.init)
                self.init_thread.start()
                return


        except Exception as e:
            self.showInfoBar.emit("error", "无法执行客户端请求\n" + str(e))
            return

    def init(self):
        try:
            self.showProgressDialog.emit("设备环境初始化。。。")
            # https://github.com/zhengjim/camille/pull/32/commits/1be9236d7b0d8d4369ba0e0e84df5c660dc35c87
            # 重启一下 adb, 防止 adb 偶尔抽风
            # 停止 adb
            subprocess.call(self.stop_adb_cmd)
            # 启动adb
            subprocess.call(self.start_adb_cmd)
            time.sleep(5)
            # https://github.com/zhengjim/camille/pull/32/commits/e3084d92ba0db4206409246d5e8145c9b5820640
            subprocess.call(self.devices_cmd)
            # 关闭SELinux
            subprocess.call(self.colse_SELinux_cmd)
            # https://github.com/frida/frida/issues/1788 适配ROM
            subprocess.call(self.close_usap_cmd)
            # kill 可能残留的进程
            subprocess.call(self.kill_cmd)
            time.sleep(2)
            # 获取手机架构
            self.detecting_phone_architecture()
            self.update_cmd()
            # 清理数据
            subprocess.call(self.clean_cmd)
            # 推送 frida-server 到设备
            subprocess.call(self.push_cmd)
            time.sleep(3)
            # 移动文件
            subprocess.call(self.mv_cmd)
            # 设置权限
            subprocess.call(self.chmod_cmd)
            # 启动
            pid = subprocess.Popen(self.run_cmd)
            time.sleep(5)
            pid.kill()
            if pid.returncode != None:
                raise Exception("启动失败")
            self.showInfoBar.emit("success", "初始化成功")
            self.updateAppList.emit(getAppList(), True)
            self.closeProgressDialog.emit()

        except Exception as e:
            self.showInfoBar.emit("error", "初始化错误: " + str(e))
            self.closeProgressDialog.emit()
            return



