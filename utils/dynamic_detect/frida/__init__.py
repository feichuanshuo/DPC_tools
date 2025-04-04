import subprocess
import time
import traceback
import uuid
from threading import Thread

import frida
from frida import ServerNotRunningError
from loguru import logger
from utils.dynamic_detect.frida.cmd import stop_adb_cmd, start_adb_cmd, colse_SELinux_cmd, close_usap_cmd, kill_cmd, \
    detecting_phone_architecture_cmd, clean_cmd
from configuration import adb_path, frida_server_arm, frida_server_x86, hook_script_path
from utils.dynamic_detect.frida.third_party_sdk import ThirdPartySdk


push_cmd = []
mv_cmd = []
chmod_cmd = []
run_cmd = []

# 获取手机的架构
def detecting_phone_architecture():
    result = subprocess.Popen(detecting_phone_architecture_cmd, stdout=subprocess.PIPE).communicate()
    outdata = result[0].decode("utf-8")
    if "arm" in outdata:
        return "hluda-server-arm64"
    elif "x86" in outdata:
        return "hluda-server-x86"
    else:
        raise Exception("手机架构不支持", outdata)

# 获取指定应用的pid
def get_pid(package_name):
    # 构建adb命令
    cmd = f"adb shell ps | grep {package_name} | head -n 1 | awk '{{print $2}}'"

    # 执行命令并获取输出
    result = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()

    outdata = result[0].decode("utf-8")

    return int(outdata) if outdata else 0

def frida_init():
    logger.info("frida 开始初始化！")
    try:
        # 关闭SELinux
        subprocess.call(colse_SELinux_cmd)
        # https://github.com/frida/frida/issues/1788 适配ROM
        subprocess.call(close_usap_cmd)
        # kill 可能残留的进程
        subprocess.call(kill_cmd)
        time.sleep(2)
        # 获取手机架构
        frida_server = detecting_phone_architecture()

        if frida_server == "hluda-server-arm64":
            frida_server_file = frida_server_arm
        else:
            frida_server_file = frida_server_x86

        # 将Frida服务器二进制文件推送到设备上的/storage/emulated/0目录。
        push_cmd = [adb_path, "push", frida_server_file, "/storage/emulated/0/{}".format(frida_server)]

        # 将Frida服务器二进制文件移动到设备上的/data/local/tmp目录。
        mv_cmd = [
            adb_path,
            "shell",
            "su -c 'mv /storage/emulated/0/{} /data/local/tmp/'".format(frida_server),
        ]

        # 更改Frida服务器二进制文件的权限。
        chmod_cmd = [
            adb_path,
            "shell",
            "su -c 'chmod 777 /data/local/tmp/{}'".format(frida_server),
        ]

        # 在设备上启动Frida服务器。
        run_cmd = [adb_path, "shell", "su -c 'nohup /data/local/tmp/{} &'".format(frida_server)]

        # 清理数据
        subprocess.call(clean_cmd)
        # 推送 frida-server 到设备
        subprocess.call(push_cmd)
        time.sleep(3)
        # 移动文件
        subprocess.call(mv_cmd)
        # 设置权限
        subprocess.call(chmod_cmd)
        # 启动
        pid = subprocess.Popen(run_cmd)
        time.sleep(5)
        pid.kill()
        if pid.returncode != None:
            raise Exception("启动失败")
        logger.success("frida 初始化成功！")
    except Exception as e:
        logger.error(f'frida 初始化失败！{e}')


class FridaHook:
    def __init__(self, app_name="", permission=None, wait_time=2):
        # 应用pid
        if permission is None:
            permission = {}
        self.app_pid = get_pid(app_name)
        # 应用名称
        self.app_name = app_name
        # 延时Hook时间
        self.wait_time = wait_time
        # hook线程id
        self._hook_thread_id = uuid.uuid4().hex
        # hook线程
        self._hook_thread = Thread(
            name="frida_hook_" + self._hook_thread_id, target=self.fridaHook, args=(), daemon=True
        )
        # frida会话
        self._frida_session = None
        # frida脚本
        self._frida_script = None
        # 是否hook成功
        self.is_hook = False
        # 第三方SDK
        self.tps = ThirdPartySdk()
        # 检测结果
        self.result = permission

    # 消息处理函数
    def my_message_handler(self, message, payload):
        """ 消息处理 """
        if message["type"] == "error":
            self.stop()
            return
        if message['type'] == 'send':
            data = message['payload']
            if data['type'] == 'notice':
                alert_time = data['time']
                action = data['action']
                arg = data['arg']
                messages = data['messages']
                stacks = data['stacks']
                subject_type = self.tps.is_third_party(stacks)

                print("------------------------------start---------------------------------")
                print("[*] {0}，APP行为：{1}、行为主体：{2}、行为描述：{3}、传入参数：{4}".format(
                    alert_time, action, subject_type, messages['detail'], arg.replace('\r\n', '，')))
                print("[*] 调用堆栈：")
                print(stacks)
                print("-------------------------------end----------------------------------")
                # 数据处理
                if messages['bigType'] not in self.result.keys():
                    self.result[messages['bigType']] = {
                        messages['smallType']: [messages['detail']]
                    }
                elif messages['smallType'] not in self.result[messages['bigType']].keys():
                    self.result[messages['bigType']][messages['smallType']] = [messages['detail']]
                elif messages['detail'] not in self.result[messages['bigType']][messages['smallType']]:
                    self.result[messages['bigType']][messages['smallType']].append(messages['detail'])

            elif data["type"] == "app_name":
                my_data = False if data["data"] == self.app_name else True
                self._frida_script.post({"my_data": my_data})
            elif data['type'] == 'isHook':
                print("hook成功")
                self.is_hook = True
            elif data['type'] == 'noFoundModule':
                # fixme 无用模块
                self._frida_session.detach()
                logger.error('输入 {} 模块错误，请检查'.format(data['data']))
            elif data['type'] == 'loadModule':
                if data['data']:
                    logger.success('已加载模块{}'.format(','.join(data['data'])))
                else:
                    logger.error('无模块加载，请检查')

    # hook
    def fridaHook(self):
        try:
            # 获取设备
            device = frida.get_usb_device(timeout=5)
            # sleep(1)
            # 将frida附着到指定app
            self._frida_session = device.attach(self.app_pid)
            time.sleep(1)
            with open(hook_script_path, "r", encoding="utf-8") as fr:
                self.script = fr.read()
            # 是否延时hook
            if self.wait_time:
                self.script += "setTimeout(main, {0}000);\n".format(str(self.wait_time))
            else:
                self.script += "setImmediate(main);\n"
            # 创建Frida脚本
            self._frida_script = self._frida_session.create_script(self.script)
            # 为脚本添加消息处理函数
            self._frida_script.on("message", self.my_message_handler)
            # 加载脚本
            self._frida_script.load()

            # device.resume(pid)

        except ServerNotRunningError:
            logger.error("Frida 服务未运行！正在重新初始化。。。")
            frida_init()
            self.fridaHook()
        except Exception as e:
            print("An unexpected error occurred: ", e)
            data = traceback.format_exc()
            logger.error(data)

    # 开始hook
    def start(self, join=False):
        self._hook_thread.start()
        logger.info("frida hook 开始！")
        if join:
            self._hook_thread.join()

    # 停止hook
    def stop(self):
        if self._frida_session is not None:
            self._frida_session.detach()
            subprocess.call(kill_cmd)
            logger.info("frida hook 停止！")
            return self.result

