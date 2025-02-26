import json

import pandas as pd

from utils.policy_analysis.policy_structure_parser import policy_structure_parser
from utils.policy_analysis.policy_sentences_classification import policy_sentences_classification
from configuration import parsed_policy_dir, policy_analysis_result_dir, APP_name_file_path

def extract_app_name(policy_path):
    """
    从隐私政策路径中提取 APP 名称
    :param policy_path: 隐私政策路径
    :return: APP 名称
    """
    # 获取文件名（去掉路径）
    file_name = policy_path.split('/')[-1]  # Windows 路径分隔符

    # 提取 APP 名称
    app_name = file_name.split('.')[-2]

    return app_name

def policy_analysis(policy_path):
    """
    隐私政策解析
    :param policy_path: 隐私政策路径
    """
    parser = policy_structure_parser(policy_path)
    if parser.parse_privacy_policy():
        parsed_sentences = parser.parsed_sentences_with_PC
    else:
        print(parser.parse_error_info)
        return
    parsed_sentences = policy_sentences_classification(parsed_sentences)

    result = {'CR1': False, 'CR2': False, 'CR3': False, 'CR4': False, 'CR5': False, 'CR6': False, 'CR7': False,
              'CR8': False, 'CR9': False, 'CR10': False, 'CR11': False, 'CR12': False, 'CR13': False, 'CR14': False,
              'CR15': False, 'CR16': False, 'CR17': False, 'CR18': False, 'CR19': False, 'CR20': False, 'CR21': False,
              'CR22': False, 'CR23': False, 'CR24': False, 'CR25': False, 'CR26': False}

    for sentence_item in parsed_sentences:
        for cr in sentence_item["compliance_rules"]:
            result["CR" + cr] = True

    with open(parsed_policy_dir, 'w', encoding='utf-8') as f:
        json.dump(parsed_sentences, f, ensure_ascii=False, indent=4)

    with open(policy_analysis_result_dir, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=4)


    # 实验数据保存
    # 定义列顺序
    result['APP'] = extract_app_name(policy_path)
    columns_order = ['APP'] + [f'CR{i}' for i in range(1, 27)]
    result_df = pd.DataFrame([result])  # 将字典转换为 DataFrame
    result_df = result_df[columns_order]  # 按指定顺序排列列
    result_df.to_csv('utils/policy_analysis/experiment_data.csv', mode='a', header=False, index=False)  # 保存到 CSV 文件

    # fixme: 临时代码
    # with open(APP_name_file_path, 'w', encoding='utf-8') as f:
    #     f.write(result['APP'])

    return result


if __name__ == '__main__':
    # policy_analysis("../../example/privacy_policy/抖音隐私政策.txt")
    extract_app_name("../../example/privacy_policy/抖音隐私政策.txt")
