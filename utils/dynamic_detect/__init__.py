import json
import os
import subprocess
import time

from androguard.core.apk import APK
from loguru import logger

from utils.dynamic_detect.RL_application_env import RLApplicationEnv
from utils.dynamic_detect.algorithms.QLearnExploration import QLearnAlgorithm
from utils.dynamic_detect.algorithms.RandomExploration import RandomAlgorithm
from utils.dynamic_detect.algorithms.SACExploration import SACAlgorithm
from utils.dynamic_detect.frida import frida_init
from utils.dynamic_detect.frida.cmd import stop_adb_cmd, start_adb_cmd
from configuration import adb_path

# 最大步数
timesteps = 600
# 每轮最大执行时间
timer = 6

# 模拟器检测
def emulator_detect():
    # https://github.com/zhengjim/camille/pull/32/commits/1be9236d7b0d8d4369ba0e0e84df5c660dc35c87
    # 重启一下 adb, 防止 adb 偶尔抽风
    # 停止 adb
    subprocess.call(stop_adb_cmd)
    # 启动adb
    subprocess.call(start_adb_cmd)
    time.sleep(1)
    emulators = {
        "BlueStacks or 雷神安卓模拟器 or 腾讯手游助手 or Genymotion": [5555],
        "夜神模拟器": [62001, 52001],
        "海马玩模拟器": [26944],
        "mumu模拟器": [7555],
        "天天模拟器": [6555],
        "逍遥安卓模拟器": [21503],
    }
    logger.info("开始连接模拟器！")
    for emulator_name, ports in emulators.items():
        try:
            # 尝试连接模拟器
            for port in ports:
                logger.info(f"尝试连接 {emulator_name} 端口 {port}...")
                subprocess.run(f"{adb_path} connect 127.0.0.1:{port}", shell=True, check=True)
            # 检查连接状态
            result = subprocess.run(f"{adb_path} devices", shell=True, capture_output=True, text=True)
            if emulator_name in result.stdout or f"127.0.0.1:{port}" in result.stdout:
                logger.success(f"{emulator_name} 连接成功！")
                return
            else:
                logger.warning(f"{emulator_name} 连接失败，正在尝试连接其他模拟器。。。")
        except Exception as e:
            logger.error(f"连接 {emulator_name} 时发生错误：{e}")




def dynamic_detect(apk_path, algorithm, N):
    """
    动态检测
    :param apk_path: apk路径
    :param algorithm: 算法
    :param N: 检测总轮次
    """
    apk = APK(apk_path)
    # APP 名称
    app_name = apk.get_app_name()
    # APK 的包名
    package_name = apk.get_package()
    # 应用的版本名
    version_name = apk.get_androidversion_name()
    # 目标 SDK 版本
    target_sdk_version = apk.get_target_sdk_version()
    activities = apk.get_activities()
    activity_dict = dict()
    for activity in activities:
        activity = activity.replace("..", ".")
        activity_dict.update({activity: {'visited': False}})
    activity_list = list(activity_dict.keys())
    # with open('activity_list.json', 'w', encoding='utf-8') as f:
    #     json.dump(activity_list, f, ensure_ascii=False, indent=4)
    personal_information = {}
    permission = {}
    logger.info("开始检测")

    # 检测模拟器
    emulator_detect()
    # frida 初始化
    frida_init()

    if algorithm == "random":
        algorithms = RandomAlgorithm()
    elif algorithm == "q_learn":
        algorithms = QLearnAlgorithm()
    else:
        algorithms = SACAlgorithm()
    # 动态检测
    total_visited_activities = set()
    cycle = 1
    while cycle <= N:
        app = RLApplicationEnv(package=package_name, activity_dict=activity_dict,
                               activity_list=activity_list, personal_information=personal_information,
                               permission=permission)
        logger.info(f'app: {package_name}, test {cycle} of {N} starting')
        if algorithm == "sac":
            if cycle == 1:
                flag = algorithms.explore(app, timesteps, timer, save_policy=True)
            else:
                flag = algorithms.explore(app, timesteps, timer, reload_policy=True, save_policy=True)
        else:
            flag = algorithms.explore(app, timesteps, timer)
        total_visited_activities = total_visited_activities.union(app.get_visited_activity())
        if flag:
            logger.success("检测完成")
        else:
            logger.error("检测失败")
            break
        personal_information = app.personal_information
        permission = app.permission
        cycle += 1
    activity_coverage = len(total_visited_activities) / len(activity_list)
    result_dir = f"results/{package_name}"
    if os.path.exists(result_dir) is False:
        os.makedirs(result_dir)
    with open(f'{result_dir}/activity_coverage.txt', 'a', encoding='utf-8') as f:
        f.write(f"{algorithm}    activity 覆盖率: {activity_coverage}\n")
    # with open(f'{result_dir}/gui_pi_{algorithm}.json', 'w', encoding='utf-8') as f:
    #     json.dump(personal_information, f, ensure_ascii=False, indent=4)
    # with open(f'{result_dir}/api_pi_{algorithm}.json', 'w', encoding='utf-8') as f:
    #     json.dump(permission, f, ensure_ascii=False, indent=4)


    # fixme 临时代码
    # with open('results/002.com.gf.client/gui_pi_sac.json', 'r', encoding='utf-8') as f:
    #     personal_information = json.load(f)
    # with open('results/002.com.gf.client/api_pi_sac.json', 'r', encoding='utf-8') as f:
    #     permission = json.load(f)


    # 合并personal_information和permission
    personal_information.update(permission)
    with open(f'{result_dir}/pi_{algorithm}.json', 'w', encoding='utf-8') as f:
        json.dump(personal_information, f, ensure_ascii=False, indent=4)

    # todo:保存RPIS到本地

    return {
        'APPInfo': {
            "app_name": app_name,
            "package_name": package_name,
            "version_name": version_name,
            "target_sdk_version": target_sdk_version
        },
        'DetectResult': personal_information
    }