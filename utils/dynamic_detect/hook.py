# hook
import logging
import os
import traceback
from time import sleep
import uuid
from threading import Thread
import frida
import uiautomator2 as u2
from PySide6.QtCore import QObject, Signal
from PySide6.QtGui import Qt
from qfluentwidgets import InfoBar, InfoBarPosition

from components import ProgressDialog
from utils import print_msg
from utils.dynamic_detect.third_party_sdk import ThirdPartySdk
from components.ResultWindow.DynamicDetect import DynamicDetect

# hook脚本路径
hook_script_path = (
        os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
        + os.sep
        + "hook_script"
        + os.sep
        + "script.js"
)


class FridaHook(QObject):
    # 注册信号
    setResult = Signal(dict)
    showInfoBar = Signal(str, str)

    def __init__(self, parent=None):
        super().__init__()
        self.parent = parent
        # APK 路径
        self.apk_path = ""
        # 应用名
        self.app_name = ""
        # 应用pid
        self.app_pid = 0
        # 延时
        self.wait_time = 0
        # hook脚本
        self.script = ""
        # hook线程id
        self.hook_thread_id = uuid.uuid4().hex
        # hook线程
        self._hook_thread = Thread(
            name="frida_hook_" + self.hook_thread_id, target=self.hook, args=(), daemon=True
        )
        # frida会话
        self._frida_session = None
        # frida脚本
        self._frida_script = None
        # 是否hook成功
        self.is_hook = False
        # 第三方SDK
        self.tps = ThirdPartySdk()
        # 动态检测的相关调用情况
        # 是否有隐私政策弹窗
        self.has_privacy_popup = "否"
        # 是否同意隐私政策
        self.accept_privacy_policy = False
        # 同意隐私政策
        self.accepted_result = {
            'log': [],
            'count': {
                '申请权限': 0,
                '获取电话相关信息': 0,
                '获取系统信息': 0,
                '获取其他app信息': 0,
                '获取位置信息': 0,
                '获取网络信息': 0,
                '调用摄像头': 0,
                '获取蓝牙设备信息': 0,
                '文件操作': 0,
                '获取麦克风': 0,
                '获取传感器信息': 0,
            },
        }
        # 拒绝隐私政策
        self.refused_result = {
            'log': [],
            'count': {
                '申请权限': 0,
                '获取电话相关信息': 0,
                '获取系统信息': 0,
                '获取其他app信息': 0,
                '获取位置信息': 0,
                '获取网络信息': 0,
                '调用摄像头': 0,
                '获取蓝牙设备信息': 0,
                '文件操作': 0,
                '获取麦克风': 0,
                '获取传感器信息': 0,
            },
        }
        # 结果窗口
        self.result_window = None

    # 消息处理函数
    def my_message_handler(self, message, payload):
        print(message)
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
                    alert_time, action, subject_type, messages, arg.replace('\r\n', '，')))
                print("[*] 调用堆栈：")
                print(stacks)
                print("-------------------------------end----------------------------------")

                # 保存数据
                if self.accept_privacy_policy:
                    self.accepted_result['log'].append({
                        'alert_time': alert_time,
                        'subject_type': subject_type,
                        'action': action,
                        'messages': messages,
                        'arg': arg,
                        'stacks': stacks
                    })
                    if action in self.accepted_result['count']:
                        self.accepted_result['count'][action] += 1
                else:
                    self.refused_result['log'].append({
                        'alert_time': alert_time,
                        'subject_type': subject_type,
                        'action': action,
                        'messages': messages,
                        'arg': arg,
                        'stacks': stacks
                    })
                    if action in self.refused_result['count']:
                        self.refused_result['count'][action] += 1
            elif data["type"] == "app_name":
                my_data = False if data["data"] == self.app_name else True
                self._frida_script.post({"my_data": my_data})
            elif data['type'] == 'isHook':
                print("hook成功")
                self.is_hook = True
            elif data['type'] == 'noFoundModule':
                # fixme 无用模块
                self._frida_session.detach()
                print_msg('输入 {} 模块错误，请检查'.format(data['data']))
            elif data['type'] == 'loadModule':
                if data['data']:
                    print_msg('已加载模块{}'.format(','.join(data['data'])))
                else:
                    print_msg('无模块加载，请检查')

    def fridaHook(self):
        try:
            # 获取设备
            device = frida.get_usb_device(timeout=5)
            # sleep(1)
            # 将frida附着到指定app
            self._frida_session = device.attach(self.app_pid)
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
            self._frida_script = self._frida_session.create_script(self.script)
            # 为脚本添加消息处理函数
            self._frida_script.on("message", self.my_message_handler)
            # 加载脚本
            self._frida_script.load()

            # device.resume(pid)

        except Exception as e:
            data = traceback.format_exc()
            logging.error(data)
            self.stop()

    def hook(self):
        try:
            d = u2.connect()
        except Exception as e:
            self.showInfoBar.emit("error", "请检查设备是否连接")
            return
        self.showProgressDialog()
        d.app_install(self.apk_path)
        self.app_name = d.app_current()['package']
        app = d.session(self.app_name, attach=True)
        self.app_pid = d.app_current()['pid']
        sleep(5)
        privacy_popup = app(textContains="隐私")
        if privacy_popup.exists(timeout=2):
            print("隐私弹窗存在")
            self.has_privacy_popup = "是"
            # 不同意隐私政策时
            refuse_button = app(text="拒绝") or app(text="不同意")
            refuse_button.click()
            self.accept_privacy_policy = False
            self.fridaHook()
            sleep(5)
            self._frida_session.detach()
            # 同意隐私政策时
            app.restart()
            sleep(5)
            agree_button = app(text="同意") or app(text="允许")
            agree_button.click()
            self.accept_privacy_policy = True
            self.fridaHook()
        else:
            self.has_privacy_popup = "否"
            print("隐私弹窗不存在")

    # 开始hook
    def start(self, apk_path="", join=False):
        self.apk_path = apk_path
        self._hook_thread.start()
        if join:
            self._hook_thread.join()

    # 停止hook
    def stop(self):
        if self._frida_session is not None:
            self._frida_session.detach()
        print("已停止检测")

        self.setResult.emit({
            'app_name': self.app_name,
            'has_privacy_popup': self.has_privacy_popup,
            'refused_result': self.refused_result,
            'accepted_result': self.accepted_result,
        })

        # self.result_window = DynamicDetect(self.accepted_result)
        # self.result_window.show()

    # 动态检测进度
    def showProgressDialog(self):
        pd = ProgressDialog(self.parent, "动态检测中...", hide_cancel_button=False, cancel_button_text="停止检测")
        pd.cancelButton.clicked.connect(self.stop)
        pd.show()
