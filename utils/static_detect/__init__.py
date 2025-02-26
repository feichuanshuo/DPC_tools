import json

from utils.static_detect.gui_analyzer import gui_analyzer
from utils.static_detect.permission_api_analyzer import permission_api_analyzer
from configuration import RPIS_SD_file_path

def static_detect(apk_path):
    """
    静态检测
    :param apk_path: apk路径
    """

    RPIS = {}
    app_info,RPIS = permission_api_analyzer(apk_path, RPIS)
    RPIS = gui_analyzer(apk_path, RPIS)

    with open(RPIS_SD_file_path,'w', encoding='utf-8') as f:
        json.dump(RPIS, f, ensure_ascii=False, indent=4)

    # fixme: 保存实验数据
    result_dir = 'utils/static_detect/experiment_data/'
    file_name =  apk_path.split('/')[-1][:-4]

    with open(result_dir + file_name + '.json', 'w', encoding='utf-8') as f:
        json.dump(RPIS, f, ensure_ascii=False, indent=4)

    return {
        'APPInfo': app_info,
        'DetectResult': RPIS
    }