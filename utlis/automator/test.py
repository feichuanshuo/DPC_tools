from utlis.automator.RL_application_env import RLApplicationEnv
from androguard.core.apk import APK
from utlis.automator.algorithms.RandomExploration import RandomAlgorithm


apk_path = "../../test0/APK/com.yinxiang.website.10.8.38.2029691.allArch.signed.latest.apk"
a = APK(apk_path)
apk_name = a.get_package()
activities = a.get_activities()
activity_dict = dict()
for activity in activities:
    activity = activity.replace("..", ".")
    activity_dict.update({activity: {'visited': False}})

print("开始测试")


app = RLApplicationEnv(package=apk_name, activity_dict=activity_dict, activity_list=list(activity_dict.keys()))

algorithms = RandomAlgorithm()

flag = algorithms.explore(app, 3600, 60)


if flag:
    print("测试完成")
else:
    print("测试失败")