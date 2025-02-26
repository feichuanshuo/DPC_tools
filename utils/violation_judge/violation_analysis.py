import json

from configuration import parsed_policy_dir, policy_analysis_result_dir, DPIS_file_path, RPIS_SD_file_path, RPIS_DD_file_path

def collect_scope_judge(DPIS, RPIS):
    """
    收集范围判定
    return:False表示超范围,True表示未超范围
    """
    for key in RPIS.keys():
        if key not in DPIS.keys():
            return False
        for item in RPIS[key]:
            if item not in DPIS[key]:
                return False
    return True

def v1_analysis(policy_analysis_result):
    """
    检测项：未提供完整的隐私政策
    策略：缺少一些必要的信息（包括CR1-CR8、CR10-CR11、CR13-CR15和CR17）
    """
    # 未提供完整的隐私政策
    if (policy_analysis_result['CR1'] and policy_analysis_result['CR2']
            and policy_analysis_result['CR3'] and policy_analysis_result['CR4']
            and policy_analysis_result['CR5'] and policy_analysis_result['CR6']
            and policy_analysis_result['CR7'] and policy_analysis_result['CR8']
            and policy_analysis_result['CR10'] and policy_analysis_result['CR11']
            and policy_analysis_result['CR13'] and policy_analysis_result['CR14']
            and policy_analysis_result['CR15'] and policy_analysis_result['CR17']):
        return {
            'violation': False,
            'message': '合规'
        }
    else:
        return {
            'violation': True,
            'message': '未提供完整的隐私政策'
        }

def v2_analysis():
    """
    检测项：未公开收集使用规则
    策略: 动态检测时，检测是否有隐私弹窗
    """
    return {
        'violation': False,
        'message': '合规'
    }

def v3_analysis(policy_analysis_result,has_ETC):
    """
    检测项：未明示收集使用个人信息的目的、方式和范围
    策略：缺少CR11、CR13 2.存在CR18，但缺少CR21、CR22
         缺少CR7
         在带有 CR13 标签的句子中，在 PI 之后立即检测到 ETC（歧义） 单词
    """
    message = ''
    if (not policy_analysis_result['CR11'] or not policy_analysis_result['CR13']
            or (policy_analysis_result['CR18'] and not policy_analysis_result['CR21'] and not policy_analysis_result[
                'CR22'])):
        if message != '':
            message += '\n'
        message += '未逐一列出App(包括委托的第三方或嵌入的第三方代码、插件)收集使用个人信息的目的、方式、范围等'
    if not policy_analysis_result['CR7']:
        if message != '':
            message += '\n'
        message += '收集使用个人信息的目的、方式、范围发生变化时，未以适当方式通知用户，适当方式包括更新隐私政策等收集使用规则并提醒用户阅读等'
    if has_ETC:
        if message != '':
            message += '\n'
        message += '使用模棱两可的语言描述要收集的个人信息'
    if message != '':
        return {
            'violation': True,
            'message': message
        }
    else:
        return {
            'violation': False,
            'message': '合规'
        }

def v4_analysis(policy_analysis_result):
    """
    检测项：未经用户同意收集使用个人信息
    策略：缺少CR6
        实际使用的个人信息大于声明的范围
        存在CR12，但缺少CR9
    """
    with open(DPIS_file_path, 'r', encoding='utf-8') as f:
        DPIS_file = json.load(f)
    with open(RPIS_SD_file_path, 'r', encoding='utf-8') as f:
        RPIS_SD_file = json.load(f)
    with open(RPIS_DD_file_path, 'r', encoding='utf-8') as f:
        RPIS_DD_file = json.load(f)

    DPIS = {}
    RPIS_SD = {}
    RPIS_DD = {}
    for key in DPIS_file.keys():
        DPIS[key] = list(DPIS_file[key].keys())
    for key in RPIS_SD_file.keys():
        RPIS_SD[key] = list(RPIS_SD_file[key].keys())
    for key in RPIS_DD_file.keys():
        RPIS_DD[key] = list(RPIS_DD_file[key].keys())

    SD_RES = collect_scope_judge(DPIS, RPIS_SD)
    DD_RES = collect_scope_judge(DPIS, RPIS_DD)

    message = ''

    if not policy_analysis_result['CR6']:
        if message != '':
            message += '\n'
        message += '收集个人信息或打开可收集个人信息的权限不需要征得用户同意'
    if policy_analysis_result['CR12'] and not policy_analysis_result['CR9']:
        if message != '':
            message += '\n'
        message += '利用用户个人信息和算法定向推送信息，未提供非定向推送信息的选项'
    if (not SD_RES) and (not DD_RES):
        if message != '':
            message += '\n'
        message += '实际使用的个人信息大于声明的范围(高风险)'
    elif not SD_RES:
        if message != '':
            message += '\n'
        message += '实际使用的个人信息大于声明的范围(中风险)'
    elif not DD_RES:
        if message != '':
            message += '\n'
        message += '实际使用的个人信息大于声明的范围(低风险)'
    if message != '':
        return {
            'violation': True,
            'message': message
        }
    else:
        return {
            'violation': False,
            'message': '合规'
        }

def v5_analysis(policy_analysis_result):
    """
    检测项：未经同意向他人提供个人信息
    策略：存在CR18，但不存在CR19-CR22
        存在CR23，但不存在CR24-CR26
    """
    message = ''
    if (policy_analysis_result['CR18'] and not policy_analysis_result['CR19'] and not policy_analysis_result['CR20']
            and not policy_analysis_result['CR21'] and not policy_analysis_result['CR22']):
        if message != '':
            message += '\n'
        message += '未提供有关个人信息共享的足够信息'
    if (policy_analysis_result['CR23'] and not policy_analysis_result['CR24'] and not policy_analysis_result['CR25']
          and not policy_analysis_result['CR26']):
        if message != '':
            message += '\n'
        message += '未提供有关个人信息跨境传输的足够信息'
    if message != '':
        return {
            'violation': True,
            'message': message
        }
    else:
        return {
            'violation': False,
            'message': '合规'

        }

def v6_analysis(policy_analysis_result):
    """
    检测项：未按法律规定提供删除或更正个人信息功能
    策略：缺少CR10
    """
    if not policy_analysis_result['CR10']:
        return {
            'violation': True,
            'message': '未提供删除或更正个人信息的功能'
        }
    return {
        'violation': False,
        'message': '合规'
    }

def violation_analysis(has_ETC):
    with open(policy_analysis_result_dir, 'r', encoding='utf-8') as f:
        policy_analysis_result = json.load(f)
    result = {
        'v1': v1_analysis(policy_analysis_result),
        'v2': v2_analysis(),
        'v3': v3_analysis(policy_analysis_result,has_ETC),
        'v4': v4_analysis(policy_analysis_result),
        'v5': v5_analysis(policy_analysis_result),
        'v6': v6_analysis(policy_analysis_result)
    }

    return result
