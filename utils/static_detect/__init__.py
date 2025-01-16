from utils.static_detect.gui_analyzer import gui_analyzer
from utils.static_detect.permission_api_analyzer import permission_api_analyzer

def static_detect(apk_path):
    """
    静态检测
    :param apk_path: apk路径
    """

    RPIS = {}
    app_info,RPIS = permission_api_analyzer(apk_path, RPIS)
    RPIS = gui_analyzer(apk_path, RPIS)

    # todo:保存RPIS到本地

    return {
        'APPInfo': app_info,
        'DetectResult': RPIS
    }