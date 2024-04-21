# hook
import logging
import os
import signal
import traceback
from time import sleep
import uuid
from threading import Thread
import frida

# hook脚本路径
hook_script_path = (
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
    + os.sep
    + "hook_script"
    + os.sep
    + "script.js"
)

class FridaHook():
    def __init__(self, appname, wait_time=0, is_attach=False):
        # 应用名
        self.app_name = appname
        # 延时
        self.wait_time = wait_time
        # hook脚本
        self.script = ""
        # hook线程id
        self.hook_thread_id: str = uuid.uuid4().hex
        # hook线程
        self.hook_thread = Thread(
            name="frida_hook_" + self.hook_thread_id, target=self.fridaHook, args=(), daemon=True
        )
        # frida会话
        self.frida_session = None
        # frida脚本
        self.frida_script = None

    # 消息处理函数
    def my_message_handler(self, message, payload):
        print(message)
        """ 消息处理 """
        if message["type"] == "error":
            self.stop()
            return
        if message['type'] == 'send':
            print(message)
            pass

    def fridaHook(self):

        try:
            # 获取设备
            device = frida.get_usb_device(timeout=5)
            # 获取进程id
            pid = device.spawn([self.app_name])
            sleep(1)
            # 将frida附着到指定app
            self.frida_session = device.attach(pid)
            sleep(1)
            with open(hook_script_path, "r", encoding="utf-8") as fr:
                self.script = fr.read()
                # 是否延时hook
            wait_time = 2
            if wait_time:
                self.script += "setTimeout(main, {0}000);\n".format(str(wait_time))
            else:
                self.script += "setImmediate(main);\n"
            # 创建Frida脚本
            self.frida_script = self.frida_session.create_script(self.script)
            # 为脚本添加消息处理函数
            self.frida_script.on("message", self.my_message_handler)
            # 加载脚本
            self.frida_script.load()

            device.resume(pid)


        except Exception as e:
            data = traceback.format_exc()
            logging.error(data)
            self.stop()

    # 开始hook
    def start(self,jion=False):
        self.hook_thread.start()
        if jion:
            self.hook_thread.join()
    # 停止hook
    def stop(self):
        if self.frida_session != None:
            self.frida_session.detach()