
from utils.automator.RL_application_env import RLApplicationEnv
from androguard.core.apk import APK
from utils.automator.algorithms.RandomExploration import RandomAlgorithm
from utils.automator.algorithms.QLearnExploration import QLearnAlgorithm
from loguru import logger


apk_path = "../../test0/APK/com.yinxiang.website.10.8.38.2029691.allArch.signed.latest.apk"
a = APK(apk_path)
apk_name = a.get_package()
activities = a.get_activities()
activity_dict = dict()
for activity in activities:
    activity = activity.replace("..", ".")
    activity_dict.update({activity: {'visited': False}})

print("开始测试")
# 训练总轮次
N = 10

app = RLApplicationEnv(package=apk_name, activity_dict=activity_dict, activity_list=list(activity_dict.keys()))

algorithms = RandomAlgorithm()
# algorithms = QLearnAlgorithm()

cycle = 0

while cycle < N:
    logger.info(f'app: {apk_name}, test {cycle} of {N} starting')
    flag = algorithms.explore(app, 3600, 60)

    print(app.get_activity_coverage())


    if flag:
        print("测试完成")
    else:
        print("测试失败")
