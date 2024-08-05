"""
违规判定
"""
import json
from utils.violation_judge.extract_DPIS import extract_DPIS
from configuration import parsed_policy_dir


def violation_judge():
    # 声明的个人信息集
    DPIS = {}
    # 获取解析后的隐私政策
    with open(parsed_policy_dir, 'r', encoding='utf-8') as f:
        parsed_policy = json.load(f)
    # 提取隐私政策中声明的个人信息集
    for sentence_item in parsed_policy:
        if '13' in sentence_item['compliance_rules']:
            extract_DPIS(sentence_item['sentence'], DPIS)
    with open('DPIS.json', 'w', encoding='utf-8') as f:
        json.dump(DPIS, f, ensure_ascii=False, indent=4)

    return {}
