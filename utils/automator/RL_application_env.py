"""
强化学习环境
"""
import subprocess
from loguru import logger
import numpy
from gym import Env, spaces
import uiautomator2 as u2
from hashlib import md5
import time
from utils.automator.gui_analysis import extract_PI


class RLApplicationEnv(Env):
    def __init__(self, apk_path, package, activity_dict, activity_list,
                 max_episode_len=250, OBSERVATION_SPACE=2000, ACTION_SPACE=30):
        # 包名
        self.package = package
        # 观察空间(state)
        self.OBSERVATION_SPACE = OBSERVATION_SPACE
        # 动作空间(action)
        self.ACTION_SPACE = ACTION_SPACE
        # 包含的个人信息
        self.personal_information = {}
        # 最大测试周期步数
        self._max_episode_steps = max_episode_len
        # activity 列表(用于one-hot编码确定activity编号)
        self.activity_list = activity_list
        # 控件列表(用于one-hot编码确定控件编号)
        self.widget_list = []
        # activity 字典(判断activity是否已经被访问过，及包含的控件)
        self.activity_dict = activity_dict
        # 当前xml
        self.current_xml = None
        # 当前是否处于应用外
        self.outside = False

        # 启动adb
        subprocess.call(["adb", "start-server"])

        '''
        初始化环境
        '''
        self.device = u2.connect()
        # 检测是否已经安装 APK
        is_installed = subprocess.run(['adb', 'shell', f'pm list packages | grep {package}'], capture_output=True, text=True).returncode == 0
        if not is_installed:
            # 安装 APK
            self.device.app_install(apk_path)
        self.app = self.device.session(self.package)
        # # 隐私政策处理
        # privacy_popup = self.app(textContains="隐私")
        # if privacy_popup.exists(timeout=2):
        #     # 同意隐私政策
        #     agree_button_text = ["同意", "允许", "同意并继续", "我同意"]
        #     for text in agree_button_text:
        #         agree_button = self.app(text=text)
        #         if agree_button.exists(timeout=2) and agree_button.info.get('clickable') == "true":
        #             agree_button.click()
        #             break
        self.current_activity = self.rename_activity(self.device.app_current()['activity'])
        self.old_activity = self.current_activity
        # 获取设备的窗口尺寸
        self.dims = self.device.window_size()

        # 初始化观察数组
        self.observation = numpy.array([0] * self.OBSERVATION_SPACE)
        # 测试周期内访问过的activity
        self.set_activities_episode = {self.current_activity}
        # 视图
        self.views = {}
        # md5
        self._md5 = ''
        # 时间步数
        self.timesteps = 0

        '''
        定义 gym 空间
        action(交互的小组件，输入的字符串，具体动作) 三维
        state(activity,...,widget,...) 一维
        '''
        self.action_space = spaces.Box(low=numpy.array([0, 0]),
                                       high=numpy.array([self.ACTION_SPACE, 1]),
                                       dtype=numpy.int64)
        self.observation_space = spaces.Box(low=0, high=1, shape=(self.OBSERVATION_SPACE,), dtype=numpy.int32)

        # self.get_all_views()
        logger.success('环境初始化完成')

    def step(self, action_number):
        """
        执行动作
        :param action_number:
        :return: state, reward, done, info
        """

        try:
            action_number = action_number.astype(int)
            logger.debug(f'当前动作: {action_number}')
            if action_number[0] >= self.get_action_space()[0]:
                # 如果动作编号大于动作空间的最大值，则返回-50奖励
                return self.observation, numpy.array([-50.0]), numpy.array(False), {}
            else:
                self.timesteps += 1
                return self.step2(action_number)
        except Exception as e:
            logger.error(f'Error: {e}')
            # 获取当前屏幕的XML布局
            xml = self.device.dump_hierarchy()
            with open("screen_dump/screen_dump.xml", "w") as f:
                f.write(xml)

    def step2(self, action_number):
        """
        执行动作
        :param action_number:
        :return:
        """
        if len(self.views) == 0:
            # 无可点击控件，则执行返回动作
            self.device.press('back')
            time.sleep(0.05)
        else:
            current_view = self.views[action_number[0]]

            identifier = current_view['identifier']
            self.update_button_in_activity_dict(identifier)

            logger.info(f'view: {identifier} Activity: {self.current_activity}')

            # Do Action
            self.action(current_view, action_number)
            time.sleep(0.2)
        self.outside = self.check_activity()
        if self.outside:
            self.outside = False
            # We need to reset the application
            if self.device.app_current()['activity'] is None:
                return self.observation, numpy.array([-100.0]), numpy.array(True), {}
            # You should not use an activity named launcher ( ಠ ʖ̯ ಠ)
            elif 'launcher' in self.device.app_current()['activity'].lower():
                return self.observation, numpy.array([-100.0]), numpy.array(True), {}
            # We are in another app, let's go back
            else:
                self.device.press('back')
                self.update_views()
                return self.observation, numpy.array([-100.0]), numpy.array(False), {}
        self.get_observation()
        reward = self.compute_reward()
        done = self._termination()
        return self.observation, numpy.array([reward]), numpy.array(done), {}

    def action(self, current_view, action_number):
        """
        执行动作
        :param current_view:
        :param action_number:
        :return:
        """
        logger.info(f'current_view: {current_view} action_number: {action_number}')
        # 当控件为文本框时
        if current_view['class_name'] == 'android.widget.EditText':
            pass
        else:
            # 当控件为短按按钮时
            if current_view['clickable'] and not current_view['long-clickable']:
                current_view['view'].click()

            # 当控件同时为短按按钮和长按按钮时
            elif current_view['clickable'] and current_view['long-clickable']:
                if action_number[1] == 0:
                    current_view['view'].click()
                else:
                    current_view['view'].long_click()

            # 当控件为长按按钮时
            elif not current_view['clickable'] and current_view['long-clickable']:
                current_view['view'].long_click()

            # 当控件为滚动控件时
            elif current_view['scrollable']:
                self.scroll_action(action_number)

    def scroll_action(self, action_number):
        """
        滚动动作
        :param action_number:
        :return:
        """
        # y = int((bounds[3] - bounds[1]))
        # x = int((bounds[2] - bounds[0]) / 2)
        if action_number[1] == 0:
            # 从上往下滚动
            try:
                self.device.swipe_ext('up', 0.5)
                # self.device.swipe(x, int(y * 0.5), x, int(y * 0.3), duration=200)
            # except InvalidElementStateException:
            #     logger.error(f'swipe not performed start_position: ({x}, {y}), end_position: ({x}, {y + 20})')
            except Exception as e:
                logger.error(f'Error: {e}')
        else:
            # 从下往上滚动
            try:
                self.device.swipe_ext('down', 0.5)
                # self.device.swipe(x, int(y * 0.5), x, int(y * 0.7), duration=200)
            # except InvalidElementStateException:
            #     logger.error(f'swipe not performed start_position: ({x}, {y + 20}), end_position: ({x}, {y})')
            except Exception as e:
                logger.error(f'Error: {e}')

    def compute_reward(self):
        """
        计算奖励
        :return:
        """
        # 发现个人信息的奖励
        FIND_PI_REWARD = 1000.0
        # 发现新页面的奖励
        FIND_NP_REWARD = 500.0
        if self.old_activity != self.current_activity:
            if self.current_activity not in self.set_activities_episode:
                self.set_activities_episode.add(self.current_activity)
                PI = extract_PI(self.current_xml)
                if PI:
                    # todo: 处理个人信息
                    self.deal_with_PI(PI)
                    return FIND_PI_REWARD
                else:
                    return FIND_NP_REWARD
            else:
                return 0.0
        else:
            return -1.0

    def _termination(self):
        """
        判断是否终止
        :return:
        todo: 终止条件，需要完善
        """
        if self.timesteps >= self._max_episode_steps or self.outside:
            self.outside = False
            return True
        else:
            return False

    def reset(self):
        """
        重置环境
        :return: observation
        """
        # 重置MD5值和时间步计数器
        self._md5 = ''
        self.timesteps = 0
        # 重置环境
        try:
            self.app.restart()
        except Exception as e:
            logger.error(f"Error: {e}")
        self.current_activity = self.rename_activity(self.device.app_current()['activity'])
        self.old_activity = self.current_activity
        self.set_activities_episode = {self.current_activity}
        self.get_observation()
        self.update_views()
        logger.success('环境重置完成')
        return self.observation

    def get_observation(self):
        """
        获取 state one-hot 编码
        :return:
        """
        observation_0 = self.one_hot_encoding_activities()
        observation_1 = self.one_hot_encoding_widgets()
        self.observation = numpy.array(observation_0 + observation_1)

    def one_hot_encoding_activities(self):
        """
        one-hot 编码 activity
        :return:
        """
        activity_observation = [0] * len(self.activity_list)
        if self.current_activity in self.activity_list:
            index = self.activity_list.index(self.current_activity)
            activity_observation[index] = 1
        return activity_observation

    def one_hot_encoding_widgets(self):
        """
        one-hot 编码 widgets
        :return:
        """
        widget_observation = [0] * (self.OBSERVATION_SPACE - len(self.activity_list))
        for k, item in self.views.items():
            identifier = item['identifier']
            if identifier in self.widget_list:
                index = self.widget_list.index(identifier)
                widget_observation[index] = 1
        return widget_observation

    def rename_activity(self, actual_activity):
        """
        将获取的 activity 名换为完整的名字
        :param actual_activity:
        :return: activity or None
        """
        if actual_activity is not None:
            for activity in self.activity_list:
                if activity.endswith(actual_activity):
                    return activity
        return None

    def check_activity(self):
        """
        检查当前 activity 是否发生变化
        :return:
        """
        temp_activity = self.rename_activity(self.device.app_current()['activity'])
        # If it is not a bug we could be outside the application
        if (self.package != self.device.app_current()['package']) or (temp_activity is None) or (
                temp_activity.find('com.facebook.FacebookActivity') >= 0):
            return True
        # If we have changed the activity:
        logger.info('检查当前 activity 是否发生变化')
        if self.current_activity != temp_activity:
            self.old_activity = self.current_activity
            self.current_activity = temp_activity
            logger.info('当前 activity 发生变化')
        else:
            logger.info('当前 activity 未发生变化')
        self.update_views()
        return False

    def update_views(self):
        """
        更新新页面的控件
        :return:
        """
        try:
            self.get_all_views()
        except Exception as e:
            logger.error(f'Error: {e}')
        if len(self.views) == 0:
            self.action_space.high[0] = self.ACTION_SPACE
        else:
            self.action_space.high[0] = len(self.views)

    def get_all_views(self):
        """
        获取当前页面所有可点击的控件
        :return:
        """
        page = self.device.dump_hierarchy()
        self.current_xml = page
        page = page.replace('enabled="true"', '').replace('enabled="false"', '').replace('checked="false"', '') \
            .replace('checked="true"', '')
        # 将页面进行MD5加密，判断页面是否发生变化
        temp_md5 = md5(page.encode()).hexdigest()
        if temp_md5 != self._md5:
            self._md5 = temp_md5
            self.views = {}
            # 使用 XPath 查找可点击、可长点击和可滚动的元素
            xpath_expressions = [
                '//*[@clickable="true"]',
                '//*[@longClickable="true"]',
                '//*[@scrollable="true"]'
            ]
            element_set = set()

            for xpath_expr in xpath_expressions:
                elements = self.device.xpath(xpath_expr).all()
                element_set.update(elements)

            # 去重后的元素列表
            element_list = list(element_set)

            identfier_list = []

            # 遍历元素列表并获取信息
            for index, element in enumerate(element_list):
                element_info = element.info
                clickable = element_info.get('clickable', False)
                scrollable = element_info.get('scrollable', False)
                long_clickable = element_info.get('longClickable', False)
                identifier = self.return_identifier(element_info)
                if identifier in identfier_list:
                    logger.error(f'重复控件: {identifier}')
                else:
                    identfier_list.append(identifier)
                logger.debug(f'获得控件 identifier: {identifier}')
                self.views.update({index: {'view': element, 'identifier': identifier, 'text': element_info.get('text'),
                                           'class_name': element_info.get('className'),
                                           'clickable': clickable, 'scrollable': scrollable,
                                           'long-clickable': long_clickable}})

            self.update_buttons_in_activity_dict()
            logger.success('获取当前页面控件成功')

    def return_identifier(self, element_info):
        """
        生成控件的唯一标识
        :param element_info:
        :return: identifier
        """
        resource_id = element_info.get('resourceId', '')
        content_description = element_info.get('contentDescription', '')
        text = element_info.get('text', '')
        className = element_info.get('className')
        bounds = element_info.get('bounds')
        unique_identifier = f"{className}:{bounds['left']},{bounds['top']},{bounds['right']},{bounds['bottom']}:{resource_id}:{content_description}:{text}"
        identifier = md5(unique_identifier.encode()).hexdigest()
        return identifier

    def update_buttons_in_activity_dict(self):
        """
        更新 activity 字典
        :return:
        """
        # Updating activity coverage
        if self.current_activity in self.activity_dict.keys():
            self.activity_dict[self.current_activity].update({'visited': True})
        else:
            self.activity_dict.update(
                {self.current_activity: {'visited': True}})

        # Updating views coverage
        for k, item in self.views.items():
            identifier = item['identifier']
            if identifier not in self.activity_dict[self.current_activity].keys():
                self.activity_dict[self.current_activity].update({identifier: False})
            if identifier not in self.widget_list:
                self.widget_list.append(identifier)

    def update_button_in_activity_dict(self, identifier):
        """
        更新 activity 字典, 标记控件已点击
        :param identifier
        :return:
        """
        self.activity_dict[self.current_activity].update({identifier: True})

    def get_action_space(self):
        """
        获取动作空间，用于判断action是否在空间内
        :return: 动作空间的最大值
        """
        return list(self.action_space.high)

    def get_visited_activity(self):
        """
        获取activity覆盖率
        """
        return self.set_activities_episode

    def deal_with_PI(self, PI):
        """
        处理个人信息
        """
        for key, value in PI.items():
            if key not in self.personal_information.keys():
                self.personal_information[key] = value
            else:
                for ikey, ivalue in value.items():
                    if ikey not in self.personal_information[key].keys():
                        self.personal_information[key][ikey] = ivalue
                    else:
                        self.personal_information[key][ikey].extend(ivalue)

