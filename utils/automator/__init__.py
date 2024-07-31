import json
import os

from androguard.core.apk import APK
from loguru import logger

from utils.automator.RL_application_env import RLApplicationEnv
from utils.automator.algorithms.QLearnExploration import QLearnAlgorithm
from utils.automator.algorithms.RandomExploration import RandomAlgorithm
from utils.automator.algorithms.SACExploration import SACAlgorithm

timesteps = 500
timer = 3


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
    with open('activity_list.json', 'w', encoding='utf-8') as f:
        json.dump(activity_list, f, ensure_ascii=False, indent=4)
    logger.info("开始检测")

    if algorithm == "random":
        algorithms = RandomAlgorithm()
    elif algorithm == "q_learn":
        algorithms = QLearnAlgorithm()
    else:
        algorithms = SACAlgorithm()
    total_visited_activities = set()
    cycle = 1
    while cycle <= N:
        app = RLApplicationEnv(apk_path=apk_path, package=package_name, activity_dict=activity_dict,
                               activity_list=activity_list)
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
        cycle += 1
    activity_coverage = len(total_visited_activities) / len(activity_list)
    result_dir = f"results/{package_name}"
    if os.path.exists(result_dir) is False:
        os.makedirs(result_dir)
    with open(f'{result_dir}/activity_coverage.txt', 'a', encoding='utf-8') as f:
        f.write(f"{algorithm}    activity 覆盖率: {activity_coverage}\n")
    with open(f'{result_dir}/{algorithm}.json', 'w', encoding='utf-8') as f:
        json.dump(app.personal_information, f, ensure_ascii=False, indent=4)
    return {
        'APPInfo': {
            "app_name": app_name,
            "package_name": package_name,
            "version_name": version_name,
            "target_sdk_version": target_sdk_version
        },
    }