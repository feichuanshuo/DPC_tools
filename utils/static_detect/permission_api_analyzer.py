import json

from androguard.misc import AnalyzeAPK

from configuration import api_pi_path, permission_pi_path


def analyze_basic_info(a):
    """
    获取apk基本信息
    param a: an APK instance
    return: apk基本信息
    """
    return {
        'app_name': a.get_app_name(),
        'package_name': a.get_package(),
        'version_name': a.get_androidversion_name(),
        'target_sdk_version': a.get_target_sdk_version(),
    }


def find_in_code(class_list, api_config, res):
    """
    scan all classes and methods in the apk, and map them to PI
    """
    for classItem in class_list:
        className = classItem.name
        className = className.replace('/', '.')
        className = className.replace('$', '.')

        methods = classItem.get_methods()

        for methodItem in methods:
            for config in api_config:
                if config['class'] in className and (methodItem.name == config['method'] or config['method'] == '*'):
                    bigType = config['bigType']
                    smallType = config['smallType']
                    if bigType not in res.keys():
                        res[bigType] = {}
                    if smallType not in res[bigType].keys():
                        res[bigType][smallType] = []
                    if config['method'] == '*':
                        method_name = methodItem.name
                    else:
                        method_name = config['method']
                    res[bigType][smallType].append("API  {}.{}:{}".format(className[:-1], method_name, config['detail']))

    return res

def find_in_manifest(permission_list, permission_config, res):
    """
    Scan all permission_list (which is obtained from the apk manifest), and check whether permission is in permission_config.
    """

    for i in range(len(permission_list)):
        if '.' in permission_list[i]:
            permission_list[i] = permission_list[i].split('.')[-1]

    for aConfig in permission_config:
        if aConfig['permission'] in permission_list:
            if aConfig['bigType'] not in res.keys():
                res[aConfig['bigType']] = {}
            if aConfig['smallType'] not in res[aConfig['bigType']].keys():
                res[aConfig['bigType']][aConfig['smallType']] = []
            res[aConfig['bigType']][aConfig['smallType']].append("权限  {}:{}".format(aConfig['permission'],aConfig['detail']))
    return res

def permission_api_analyzer(apk_path, RPIS):
    """
    解析apk文件，获取其中的权限和API
    :param apk_path: apk文件路径
    :return: apk信息、apk文件的权限和API
    """
    app_info = {}

    try:
        a, d, dx = AnalyzeAPK(apk_path)
    except Exception as e:
        print('{}-Fail to analyze apk-{}'.format(apk_path, e))
        return None, None

    # 获取apk基本信息
    try:
        app_info = analyze_basic_info(a)
    except Exception as e:
        print('Failed to obtain apk basic information-{}'.format(e))

    # Get all classes
    class_list = dx.get_classes()

    # Get permissions names declared in the AndroidManifest.xml
    permission_list = a.get_permissions()

    # Parse apis called to PI
    with open(api_pi_path, "r", encoding="utf-8") as f:
        api_config = json.load(f)
    RPIS = find_in_code(class_list, api_config, RPIS)

    # # Parse permissions to PI
    with open(permission_pi_path, "r", encoding="utf-8") as f:
        permission_config = json.load(f)
    RPIS = find_in_manifest(permission_list, permission_config, RPIS)

    return app_info, RPIS